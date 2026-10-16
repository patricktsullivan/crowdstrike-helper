#!/usr/bin/env python
# -*-coding:utf-8 -*-

###############################################################################
    # rtr_script_runner.py
    # Runs target script stored in CrowdStrike's Response Scripts against list of hosts

    # Target hosts by hostname or Sensor ID
    # Choose script from list of scripts stored in CrowdStrike cloud

###############################################################################

import csv
import datetime
import json
import logging
import pathlib
import re
import subprocess
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed

from falconpy import Hosts, RealTimeResponse, RealTimeResponseAdmin

# Global Setup
###############################################################################
# API Credentials (leave as "___" to pull from 1Password instead)
CLIENT_ID = "___"
CLIENT_SECRET = "___"
BASE_URL = "https://api.laggar.gcw.crowdstrike.com"
MEMBER_CID = ""

# 1Password Credential Target
OP_CLIENT_ID_REF = "op://Credentials/CrowdStrike Primary Patrick/username"
OP_CLIENT_SECRET_REF = "op://Credentials/CrowdStrike Primary Patrick/credential"

REPORT_DIR = pathlib.Path(__file__).parent.resolve() / "audit_reports"
RUN_TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
OUTPUT_FILE = REPORT_DIR / f"{RUN_TIMESTAMP}__rtr_script_runner.csv"
LOG_FILE = REPORT_DIR / "api_audit_log.log"

# Keep this under 5000 for Hosts API
API_RESULT_LIMIT = 500

# RTR batch settings
# Hosts per batch session (API maximum is 10,000)
BATCH_SIZE = 1000
# Number of batch sessions to run at the same time
MAX_WORKERS = 5
# Seconds to wait for the script to finish on each host (API maximum is 600)
SCRIPT_TIMEOUT = 600
# Seconds to wait for sessions to be established
SESSION_TIMEOUT = 60
# Queue the script for hosts that are offline. Queued results are not returned by this script.
QUEUE_OFFLINE = False

# Set Targets here if you'd rather do that than use the CLI
TARGETS = []
###############################################################################

# Logging Setup
###############################################################################
REPORT_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE)]
)
###############################################################################

# 1Password CLI Credentials
###############################################################################
# Import Secret(s) from 1Password using 1Password CLI
def op_read(reference: str) -> str:
    """Read a secret from 1Password using op:// URI."""
    try:
        result = subprocess.run(
            ["op", "read", reference],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"1Password error: {e.stderr.strip()}") from e
    except FileNotFoundError:
        raise RuntimeError("1Password CLI (op) not found")


def get_credentials():
    """Use hard-coded credentials if set, otherwise read them from 1Password."""
    if CLIENT_ID != "___" and CLIENT_SECRET != "___":
        logger.info("Using hard-coded API credentials.")
        return CLIENT_ID, CLIENT_SECRET

    logger.info("Reading API credentials from 1Password.")
    return op_read(OP_CLIENT_ID_REF), op_read(OP_CLIENT_SECRET_REF)

# API Init
###############################################################################
# Initialize Falcon API Client
def init_falcon_client(client_id, client_secret, cid, mode):
    cs_creds = {
                'client_id': client_id,
                'client_secret': client_secret,
                'base_url': BASE_URL,
                }
    if cid:
        cs_creds["member_cid"] = cid

    if mode == "HOSTS":
        client = Hosts(creds=cs_creds)
    elif mode == "RTR":
        client = RealTimeResponse(creds=cs_creds)
    elif mode == "RTR_ADMIN":
        client = RealTimeResponseAdmin(creds=cs_creds)
    else:
        raise ValueError(f"Unknown client mode: {mode}")
    return client
###############################################################################

# Helper Functions
###############################################################################

def api_errors(response):
    """Pull the error list out of an API response."""
    body = response.get("body") or {}
    return body.get("errors") or []


def chunk(items, size):
    """Split a list into lists of at most `size` items."""
    return [items[i:i + size] for i in range(0, len(items), size)]


# Get Hostnames or Sensor IDs from User
def get_target_endpoints(host_api_client):
    if not TARGETS:
        logger.info("No targets hard-coded in script. Getting input from user.")
        targets = input("Enter a comma-separated list of hostnames or sensor ids: ")
    else:
        targets = TARGETS

    # Check if targets is a list of Sensor IDs or Hostnames
    target_host_ids = validate_input_targets(targets, host_api_client)

    return target_host_ids


def validate_input_targets(target_input, host_client):
    AID_PATTERN = re.compile(r"^[0-9a-f]{32}$")

    if isinstance(target_input, str):
        target_input = re.split(r"[,\s]+", target_input.strip())

    target_input = [t.strip() for t in target_input if t and t.strip()]

    aids = {t.lower() for t in target_input if AID_PATTERN.match(t.lower())}
    hostnames = [t for t in target_input if t.lower() not in aids]

    unresolved = []
    for hostname in hostnames:
        # Single quotes would break the FQL filter
        safe_hostname = hostname.replace("'", "")
        response = host_client.query_devices_by_filter(
            filter=f"hostname:'{safe_hostname}'",
            limit=API_RESULT_LIMIT,
        )
        if response["status_code"] != 200:
            logger.error("Lookup failed for %s: %s", hostname, api_errors(response))
            unresolved.append(hostname)
            continue

        found = response["body"]["resources"]
        if not found:
            unresolved.append(hostname)
            continue
        if len(found) > 1:
            logger.warning("%s matched %d devices; including all", hostname, len(found))
        aids.update(found)

    if unresolved:
        logger.warning("Could not resolve hostnames: %s", unresolved)
        print(f"[!] Could not resolve {len(unresolved)} hostname(s): {', '.join(unresolved)}")

    return sorted(aids)


def get_host_details(host_client, host_ids):
    """Return {aid: device details} for the given sensor IDs."""
    details = {}
    for id_chunk in chunk(host_ids, API_RESULT_LIMIT):
        response = host_client.get_device_details(ids=id_chunk)
        if response["status_code"] != 200:
            logger.error("Device detail lookup failed: %s", api_errors(response))
        for device in response["body"].get("resources") or []:
            details[device["device_id"]] = device

    missing = [aid for aid in host_ids if aid not in details]
    if missing:
        logger.warning("No device details for sensor IDs: %s", missing)
        print(f"[!] {len(missing)} sensor ID(s) not found in this CID and will be skipped.")

    return details


# Get list of scripts stored in the CrowdStrike cloud
def get_cloud_scripts(admin_client):
    script_ids = []
    offset = 0
    while True:
        response = admin_client.list_scripts(limit=API_RESULT_LIMIT, offset=offset)
        if response["status_code"] != 200:
            raise RuntimeError(f"Unable to list RTR scripts: {api_errors(response)}")

        resources = response["body"].get("resources") or []
        script_ids.extend(resources)
        total = response["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)
        if not resources or offset >= total:
            break

    scripts = []
    for id_chunk in chunk(script_ids, API_RESULT_LIMIT):
        response = admin_client.get_scripts_v2(ids=id_chunk)
        if response["status_code"] != 200:
            raise RuntimeError(f"Unable to get RTR script details: {api_errors(response)}")
        scripts.extend(response["body"].get("resources") or [])

    return sorted(scripts, key=lambda s: s.get("name", "").lower())


def choose_script(admin_client):
    scripts = get_cloud_scripts(admin_client)
    if not scripts:
        raise RuntimeError("No scripts found in RTR Response Scripts.")

    print("\nAvailable Response Scripts:")
    for idx, script in enumerate(scripts, start=1):
        platforms = ", ".join(script.get("platform") or [])
        description = script.get("description") or ""
        print(f"  [{idx:>3}] {script['name']}  ({platforms})  {description}")

    while True:
        choice = input("\nSelect a script by number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(scripts):
            script = scripts[int(choice) - 1]
            break
        print("Invalid selection.")

    script_args = input("Script arguments (-CommandLine), leave blank for none: ").strip()

    logger.info("Selected script %s (%s) with args %r", script["name"], script.get("id"), script_args)
    return script, script_args


def build_command_string(script_name, script_args):
    command = f'runscript -CloudFile="{script_name}"'
    if script_args:
        # Triple backticks let RTR pass arguments containing quotes untouched
        if '"' in script_args:
            command += f" -CommandLine=```{script_args}```"
        else:
            command += f' -CommandLine="{script_args}"'
    return command


def filter_hosts_by_platform(host_ids, host_details, script):
    """Drop hosts whose OS the script was not written for."""
    platforms = {p.lower() for p in script.get("platform") or []}
    if not platforms:
        return host_ids, []

    matched, skipped = [], []
    for aid in host_ids:
        host_platform = (host_details[aid].get("platform_name") or "").lower()
        (matched if host_platform in platforms else skipped).append(aid)

    if skipped:
        logger.warning("Skipping %d host(s) not on platform(s) %s: %s", len(skipped), platforms, skipped)
        print(f"[!] Skipping {len(skipped)} host(s) not running {', '.join(sorted(platforms))}.")

    return matched, skipped

###############################################################################

# RTR Functions
###############################################################################

def run_batch(rtr_client, admin_client, host_ids, command_string, batch_num):
    """Open a batch session on host_ids and run command_string. Returns {aid: result}."""
    results = {aid: {"aid": aid, "session_started": False} for aid in host_ids}

    logger.info("Batch %d: initializing sessions on %d host(s)", batch_num, len(host_ids))
    init = rtr_client.batch_init_sessions(
        host_ids=host_ids,
        queue_offline=QUEUE_OFFLINE,
        timeout=SESSION_TIMEOUT,
    )
    logger.debug("Batch %d init response: %s", batch_num, json.dumps(init["body"], default=str))

    batch_id = init["body"].get("batch_id")
    if init["status_code"] not in (200, 201) or not batch_id:
        errors = api_errors(init)
        logger.error("Batch %d: session init failed: %s", batch_num, errors)
        for result in results.values():
            result["errors"] = errors
        return results

    connected = []
    for aid, session in (init["body"].get("resources") or {}).items():
        if aid not in results:
            continue
        results[aid]["session_id"] = session.get("session_id")
        results[aid]["offline_queued"] = session.get("offline_queued", False)
        if session.get("session_id") and not session.get("errors"):
            results[aid]["session_started"] = True
            connected.append(aid)
        else:
            results[aid]["errors"] = session.get("errors")

    if not connected:
        logger.warning("Batch %d: no sessions established", batch_num)
        return results

    logger.info("Batch %d (%s): running '%s' on %d host(s)", batch_num, batch_id, command_string, len(connected))
    response = admin_client.batch_admin_command(
        batch_id=batch_id,
        base_command="runscript",
        command_string=command_string,
        optional_hosts=connected,
        timeout=SCRIPT_TIMEOUT,
    )

    if response["status_code"] not in (200, 201):
        errors = api_errors(response)
        logger.error("Batch %d: runscript failed: %s", batch_num, errors)
        for aid in connected:
            results[aid]["errors"] = errors
        return results

    for aid, output in (response["body"].get("combined", {}).get("resources") or {}).items():
        if aid not in results:
            continue
        results[aid].update({
            "complete": output.get("complete"),
            "stdout": output.get("stdout", ""),
            "stderr": output.get("stderr", ""),
            "errors": output.get("errors"),
            "task_id": output.get("task_id"),
        })

    return results


def run_script_on_hosts(rtr_client, admin_client, host_ids, command_string):
    """Split hosts into batches and run them concurrently."""
    batches = chunk(host_ids, BATCH_SIZE)
    all_results = {}

    print(f"\nRunning across {len(host_ids)} host(s) in {len(batches)} batch session(s)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(run_batch, rtr_client, admin_client, batch, command_string, num): num
            for num, batch in enumerate(batches, start=1)
        }
        for future in as_completed(futures):
            num = futures[future]
            try:
                batch_results = future.result()
            except Exception:
                logger.exception("Batch %d raised an exception", num)
                for aid in batches[num - 1]:
                    all_results[aid] = {"aid": aid, "session_started": False, "errors": "exception, see log"}
                print(f"  Batch {num}: failed (see log)")
                continue

            all_results.update(batch_results)
            done = sum(1 for r in batch_results.values() if r.get("complete"))
            print(f"  Batch {num}: {done}/{len(batch_results)} host(s) completed")

    return all_results

###############################################################################

# Output Functions
###############################################################################

def write_results(results, host_details, script_name, command_string):
    fields = ["aid", "hostname", "platform", "script", "command", "session_started",
              "offline_queued", "complete", "stdout", "stderr", "errors", "session_id", "task_id"]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for aid, result in sorted(results.items()):
            device = host_details.get(aid, {})
            row = {
                **result,
                "hostname": device.get("hostname", ""),
                "platform": device.get("platform_name", ""),
                "script": script_name,
                "command": command_string,
                "errors": json.dumps(result.get("errors")) if result.get("errors") else "",
            }
            writer.writerow(row)
            logger.info("Result for %s (%s): %s", row["hostname"], aid, json.dumps(result, default=str))

    print(f"\nResults written to {OUTPUT_FILE}")

###############################################################################


def main():
    # Get API Credentials
    client_id, client_secret = get_credentials()

    # Initialize API Clients
    host_client = init_falcon_client(client_id, client_secret, MEMBER_CID, "HOSTS")
    rtr_client = init_falcon_client(client_id, client_secret, MEMBER_CID, "RTR")
    admin_rtr_client = init_falcon_client(client_id, client_secret, MEMBER_CID, "RTR_ADMIN")

    # Get Host Targets (Sensor IDs)
    target_host_ids = get_target_endpoints(host_client)
    host_details = get_host_details(host_client, target_host_ids)
    target_host_ids = [aid for aid in target_host_ids if aid in host_details]
    if not target_host_ids:
        print("No valid targets found. Exiting.")
        return 1

    # Get Script Choice
    script, script_args = choose_script(admin_rtr_client)
    command_string = build_command_string(script["name"], script_args)

    target_host_ids, _ = filter_hosts_by_platform(target_host_ids, host_details, script)
    if not target_host_ids:
        print("No targets match the script's platform. Exiting.")
        return 1

    print(f"\nAbout to run: {command_string}")
    print(f"Against {len(target_host_ids)} host(s).")
    if input("Continue? [y/N]: ").strip().lower() != "y":
        logger.info("Run cancelled by user.")
        print("Cancelled.")
        return 0

    # Start RTR Batch Sessions with targeted hosts
    results = run_script_on_hosts(rtr_client, admin_rtr_client, target_host_ids, command_string)

    # Write results from each session to log
    write_results(results, host_details, script["name"], command_string)

    completed = sum(1 for r in results.values() if r.get("complete"))
    print(f"Completed on {completed}/{len(target_host_ids)} host(s).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
