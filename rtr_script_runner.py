#!/usr/bin/env python
# -*-coding:utf-8 -*-

###############################################################################
    # rtr_script_runner.py
    # Runs target script stored in CrowdStrike's Response Scripts against list of hosts

    # Target hosts by hostname or Sensor ID
    # Choose script from list of scripts stored in CrowdStrike cloud

###############################################################################

import argparse
import csv
import datetime
import json
import logging
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap

from concurrent.futures import ThreadPoolExecutor, as_completed

from falconpy import Hosts, OAuth2, RealTimeResponse, RealTimeResponseAdmin

# Global Setup
###############################################################################
BASE_URL = "https://api.laggar.gcw.crowdstrike.com"
MEMBER_CID = ""

# 1Password Credential Target
OP_CLIENT_ID_REF = "op://Credentials/CrowdStrike Primary Patrick/username"
OP_CLIENT_SECRET_REF = "op://Credentials/CrowdStrike Primary Patrick/credential"

REPORT_DIR = pathlib.Path(__file__).parent.resolve() / "audit_reports"
RUN_TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
OUTPUT_FILE = REPORT_DIR / f"{RUN_TIMESTAMP}__rtr_script_runner.csv"
LOG_FILE = REPORT_DIR / f"{RUN_TIMESTAMP}__rtr_script_runner.log"

# Widest the script name column gets in the script menu
MENU_NAME_WIDTH = 40

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
# Queue the script for hosts that are offline (or pass --queue-offline).
# Queued results are not returned by this script.
QUEUE_OFFLINE = False

# Set Targets here if you'd rather do that than use the CLI
TARGETS = []
###############################################################################

# Logging Setup
###############################################################################
REPORT_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"

logging.basicConfig(
    level=logging.DEBUG,
    format=LOG_FORMAT,
    handlers=[logging.FileHandler(LOG_FILE)]
)


def name_reports_for_script(script_name):
    """Rename this run's log (and the CSV to come) to include the selected script name."""
    global LOG_FILE, OUTPUT_FILE

    safe_name = re.sub(r"[^\w.-]+", "_", script_name).strip("_") or "script"
    new_log_file = REPORT_DIR / f"{RUN_TIMESTAMP}__rtr_script_runner__{safe_name}.log"
    OUTPUT_FILE = REPORT_DIR / f"{RUN_TIMESTAMP}__rtr_script_runner__{safe_name}.csv"

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if isinstance(handler, logging.FileHandler) and pathlib.Path(handler.baseFilename) == LOG_FILE:
            root_logger.removeHandler(handler)
            handler.close()

    LOG_FILE.replace(new_log_file)
    LOG_FILE = new_log_file

    file_handler = logging.FileHandler(LOG_FILE, mode="a")
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root_logger.addHandler(file_handler)
    logger.info("Log file renamed to %s", LOG_FILE)
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
    logger.info("Reading API credentials from 1Password.")
    return op_read(OP_CLIENT_ID_REF), op_read(OP_CLIENT_SECRET_REF)

# API Init
###############################################################################
# Authenticate once and share the token across all service clients
def authenticate(client_id, client_secret, cid):
    auth_kwargs = {
                'client_id': client_id,
                'client_secret': client_secret,
                'base_url': BASE_URL,
                }
    if cid:
        auth_kwargs["member_cid"] = cid

    auth = OAuth2(**auth_kwargs)
    response = auth.token()
    if response["status_code"] not in (200, 201) or not auth.token_value:
        errors = api_errors(response)
        logger.error("OAuth2 token request failed (HTTP %s): %s", response["status_code"], errors)
        raise RuntimeError(
            f"OAuth2 token request to {BASE_URL} failed with HTTP {response['status_code']}: "
            f"{format_errors(errors) or auth.token_fail_reason}"
        )

    logger.info("OAuth2 token obtained from %s (member_cid=%r)", BASE_URL, cid or None)
    return auth


def init_cid_rtr_clients(client_id, client_secret, cids, default_auth):
    """RTR sessions must be opened from the CID that owns the host, so build
    RTR and RTR Admin clients per CID. Returns {cid: (rtr_client, admin_client)}."""
    clients = {}
    for cid in sorted(cids):
        if cid == MEMBER_CID.lower():
            auth = default_auth
        else:
            try:
                auth = authenticate(client_id, client_secret, cid)
            except RuntimeError as e:
                # Expected for the API client's own CID, which is not a member of itself
                logger.warning("member_cid auth for %s failed, using default token: %s", cid, e)
                auth = default_auth
        clients[cid] = (init_falcon_client(auth, "RTR"), init_falcon_client(auth, "RTR_ADMIN"))
    return clients


# Initialize Falcon API Client
def init_falcon_client(auth, mode):
    if mode == "HOSTS":
        client = Hosts(auth_object=auth)
    elif mode == "RTR":
        client = RealTimeResponse(auth_object=auth)
    elif mode == "RTR_ADMIN":
        client = RealTimeResponseAdmin(auth_object=auth)
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


def format_errors(errors):
    """Turn an API error list into a readable one-liner."""
    if not errors:
        return ""
    return "; ".join(f"{e.get('code', '')} {e.get('message', e)}".strip() if isinstance(e, dict) else str(e)
                     for e in errors)


def report_api_failure(action, response):
    """Log and print a failed API call so 401/403s don't disappear into the log file."""
    errors = api_errors(response)
    logger.error("%s failed (HTTP %s): %s", action, response["status_code"], errors)
    message = f"[!] {action} failed (HTTP {response['status_code']}): {format_errors(errors)}"
    if response["status_code"] == 403:
        message += "\n    Check that the API client has the required scope for this call."
    print(message)


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
            report_api_failure(f"Hostname lookup for {hostname} (Hosts: Read)", response)
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
            report_api_failure("Device detail lookup (Hosts: Read)", response)
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
        response = admin_client.list_scripts(limit=100, offset=offset)
        if response["status_code"] != 200:
            report_api_failure("Listing RTR scripts (Real Time Response Admin: Write)", response)
            raise RuntimeError("Unable to list RTR scripts.")

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
            report_api_failure("Getting RTR script details (Real Time Response Admin: Write)", response)
            raise RuntimeError("Unable to get RTR script details.")
        scripts.extend(response["body"].get("resources") or [])

    return sorted(scripts, key=lambda s: s.get("name", "").lower())


def one_line(text):
    """Collapse line breaks, tabs and repeated spaces into single spaces."""
    return " ".join((text or "").split())


def truncate(text, width):
    return text if len(text) <= width else text[:width - 3].rstrip() + "..."


def print_script_menu(scripts):
    """Print one aligned row per script, trimmed to the terminal width."""
    term_width = shutil.get_terminal_size().columns
    rows = []
    for idx, script in enumerate(scripts, start=1):
        platforms = ",".join(script.get("platform") or [])
        rows.append((f"[{idx:>3}]", one_line(script.get("name")), platforms, one_line(script.get("description"))))

    name_width = min(max(len(r[1]) for r in rows), MENU_NAME_WIDTH)
    platform_width = max(len("Platform"), max(len(r[2]) for r in rows))
    prefix_width = 2 + 5 + 2 + name_width + 2 + platform_width + 2
    desc_width = max(term_width - prefix_width - 1, 10)

    print("\nAvailable Response Scripts:")
    print(f"  {'#':>5}  {'Name':<{name_width}}  {'Platform':<{platform_width}}  Description")
    print(f"  {'-' * 5}  {'-' * name_width}  {'-' * platform_width}  {'-' * min(desc_width, 11)}")
    for num, name, platforms, description in rows:
        name = truncate(name, name_width)
        description = truncate(description, desc_width)
        print(f"  {num}  {name:<{name_width}}  {platforms:<{platform_width}}  {description}")


def choose_script(admin_client):
    scripts = get_cloud_scripts(admin_client)
    if not scripts:
        raise RuntimeError("No scripts found in RTR Response Scripts.")

    print_script_menu(scripts)

    while True:
        choice = input("\nSelect a script by number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(scripts):
            script = scripts[int(choice) - 1]
            break
        print("Invalid selection.")

    description = one_line(script.get("description"))
    print(f"\nSelected: {one_line(script['name'])}")
    if description:
        print(textwrap.fill(description, width=shutil.get_terminal_size().columns - 4,
                            initial_indent="    ", subsequent_indent="    "))

    script_args = input("\nScript arguments (-CommandLine), leave blank for none: ").strip()

    logger.info("Selected script %s (%s) with args %r", script["name"], script.get("id"), script_args)
    return script, script_args


def check_script_in_cids(cid_clients, hosts_by_cid, script_name):
    """Response Scripts are stored per CID; drop CIDs that don't have the chosen script.
    Returns {aid: error} for the hosts that were dropped."""
    skipped = {}
    for cid in list(hosts_by_cid):
        _, admin_client = cid_clients[cid]
        try:
            names = {s.get("name") for s in get_cloud_scripts(admin_client)}
        except RuntimeError:
            names = set()
        if script_name in names:
            continue

        message = f"Response Script '{script_name}' not found in CID {cid}"
        logger.warning("%s; skipping %d host(s)", message, len(hosts_by_cid[cid]))
        print(f"[!] {message}; skipping {len(hosts_by_cid[cid])} host(s).")
        for aid in hosts_by_cid.pop(cid):
            skipped[aid] = {"aid": aid, "session_started": False, "errors": message}
    return skipped


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

def run_batch(rtr_client, admin_client, host_ids, command_string, batch_num, queue_offline):
    """Open a batch session on host_ids and run command_string. Returns {aid: result}."""
    results = {aid: {"aid": aid, "session_started": False} for aid in host_ids}

    logger.info("Batch %d: initializing sessions on %d host(s)", batch_num, len(host_ids))
    init = rtr_client.batch_init_sessions(
        host_ids=host_ids,
        queue_offline=queue_offline,
        timeout=SESSION_TIMEOUT,
    )
    logger.debug("Batch %d init response: %s", batch_num, json.dumps(init["body"], default=str))

    batch_id = init["body"].get("batch_id")
    if init["status_code"] not in (200, 201) or not batch_id:
        errors = api_errors(init)
        report_api_failure(f"Batch {batch_num} session init (Real Time Response: Read)", init)
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
        report_api_failure(f"Batch {batch_num} runscript (Real Time Response Admin: Write)", response)
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


def run_script_on_hosts(cid_clients, hosts_by_cid, command_string, queue_offline):
    """Split each CID's hosts into batches and run all batches concurrently."""
    batches = []
    for cid, host_ids in sorted(hosts_by_cid.items()):
        for batch in chunk(host_ids, BATCH_SIZE):
            batches.append((cid, batch))
    all_results = {}

    host_count = sum(len(b) for _, b in batches)
    print(f"\nRunning across {host_count} host(s) in {len(hosts_by_cid)} CID(s), "
          f"{len(batches)} batch session(s)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for num, (cid, batch) in enumerate(batches, start=1):
            rtr_client, admin_client = cid_clients[cid]
            logger.info("Batch %d: CID %s, %d host(s)", num, cid, len(batch))
            future = executor.submit(run_batch, rtr_client, admin_client, batch, command_string, num, queue_offline)
            futures[future] = num
        for future in as_completed(futures):
            num = futures[future]
            try:
                batch_results = future.result()
            except Exception:
                logger.exception("Batch %d raised an exception", num)
                for aid in batches[num - 1][1]:
                    all_results[aid] = {"aid": aid, "session_started": False, "errors": "exception, see log"}
                print(f"  Batch {num}: failed (see log)")
                continue

            all_results.update(batch_results)
            done = sum(1 for r in batch_results.values() if r.get("complete"))
            queued = sum(1 for r in batch_results.values() if r.get("offline_queued"))
            print(f"  Batch {num} (CID {batches[num - 1][0]}): {done}/{len(batch_results)} host(s) completed"
                  + (f", {queued} queued for offline hosts" if queued else ""))

    return all_results

###############################################################################

# Output Functions
###############################################################################

def write_results(results, host_details, script_name, command_string):
    fields = ["aid", "hostname", "cid", "platform", "script", "command", "session_started",
              "offline_queued", "complete", "stdout", "stderr", "errors", "session_id", "task_id"]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for aid, result in sorted(results.items()):
            device = host_details.get(aid, {})
            row = {
                **result,
                "hostname": device.get("hostname", ""),
                "cid": device.get("cid", ""),
                "platform": device.get("platform_name", ""),
                "script": script_name,
                "command": command_string,
                "errors": errors if isinstance(errors := result.get("errors"), str) else format_errors(errors),
            }
            writer.writerow(row)
            logger.info("Result for %s (%s): %s", row["hostname"], aid, json.dumps(result, default=str))

    print(f"\nResults written to {OUTPUT_FILE}")

###############################################################################


def parse_args():
    parser = argparse.ArgumentParser(description="Run a cloud Response Script on hosts through RTR batch sessions.")
    parser.add_argument(
        "--queue-offline",
        action="store_true",
        default=QUEUE_OFFLINE,
        help="Queue the script for offline hosts to run when they come online (results are not collected).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    logger.info("queue_offline=%s", args.queue_offline)

    # Get API Credentials
    client_id, client_secret = get_credentials()

    # Authenticate, then initialize API Clients with the shared token
    try:
        auth = authenticate(client_id, client_secret, MEMBER_CID)
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1

    host_client = init_falcon_client(auth, "HOSTS")
    admin_rtr_client = init_falcon_client(auth, "RTR_ADMIN")

    # Get Host Targets (Sensor IDs)
    target_host_ids = get_target_endpoints(host_client)
    host_details = get_host_details(host_client, target_host_ids)
    target_host_ids = [aid for aid in target_host_ids if aid in host_details]
    if not target_host_ids:
        print("No valid targets found. Exiting.")
        return 1

    # Get Script Choice
    script, script_args = choose_script(admin_rtr_client)
    name_reports_for_script(script["name"])
    command_string = build_command_string(script["name"], script_args)

    target_host_ids, _ = filter_hosts_by_platform(target_host_ids, host_details, script)
    if not target_host_ids:
        print("No targets match the script's platform. Exiting.")
        return 1

    # Group hosts by the CID that owns them; RTR must be run from that CID
    hosts_by_cid = {}
    for aid in target_host_ids:
        hosts_by_cid.setdefault(host_details[aid]["cid"].lower(), []).append(aid)
    cid_clients = init_cid_rtr_clients(client_id, client_secret, hosts_by_cid, auth)

    results = check_script_in_cids(cid_clients, hosts_by_cid, script["name"])
    target_host_ids = [aid for host_ids in hosts_by_cid.values() for aid in host_ids]
    if not target_host_ids:
        write_results(results, host_details, script["name"], command_string)
        print("No targets left to run against. Exiting.")
        return 1

    print(f"\nAbout to run: {command_string}")
    print(f"Against {len(target_host_ids)} host(s) in {len(hosts_by_cid)} CID(s).")
    if args.queue_offline:
        print("Offline hosts will have the script queued.")
    if input("Continue? [y/N]: ").strip().lower() != "y":
        logger.info("Run cancelled by user.")
        print("Cancelled.")
        return 0

    # Start RTR Batch Sessions with targeted hosts
    results.update(run_script_on_hosts(cid_clients, hosts_by_cid, command_string, args.queue_offline))

    # Write results from each session to log
    write_results(results, host_details, script["name"], command_string)

    completed = sum(1 for r in results.values() if r.get("complete"))
    print(f"Completed on {completed}/{len(results)} host(s).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
