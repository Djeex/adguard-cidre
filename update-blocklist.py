#!/usr/bin/env python3
import os
import sys
import shutil
import logging
import re
import requests
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='[update-blocklist] %(levelname)s: %(message)s',
    stream=sys.stdout
)

# Config / variables
ADGUARD_YAML = Path("/adguard/AdGuardHome.yaml")
FIRST_BACKUP = Path("/adguard/AdGuardHome.yaml.first-start.bak")
LAST_CRON_BACKUP = Path("/adguard/AdGuardHome.yaml.last-cron.bak")
MANUAL_IPS_FILE = Path("/adguard/manually_blocked_ips.conf")
CIDR_BASE_URL = "https://raw.githubusercontent.com/vulnebify/cidre/main/output/cidr/ipv4"
COUNTRIES = os.getenv("BLOCK_COUNTRIES", "")
DOCKER_API_URL = os.getenv("DOCKER_API_URL", "http://socket-proxy-adguard:2375")
CONTAINER_NAME = os.getenv("ADGUARD_CONTAINER_NAME", "adguard-home")
TMP_YAML = Path("/tmp/AdGuardHome.yaml")
TMP_DIR = Path("/tmp/cidr")

def backup_first_start():
    if not FIRST_BACKUP.exists():
        logging.info(f"Creating first-start backup: {FIRST_BACKUP}")
        shutil.copy2(ADGUARD_YAML, FIRST_BACKUP)
    else:
        logging.info("First-start backup already exists, skipping.")

def backup_last_cron():
    logging.info(f"Creating last-cron backup: {LAST_CRON_BACKUP}")
    shutil.copy2(ADGUARD_YAML, LAST_CRON_BACKUP)

def download_cidr_lists(countries):
    if not countries:
        logging.error("No countries specified in BLOCK_COUNTRIES environment variable.")
        sys.exit(1)

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    all_ips = []

    codes = [c.strip().lower() for c in countries.split(",") if c.strip()]
    for code in codes:
        url = f"{CIDR_BASE_URL}/{code}.cidr"
        logging.info(f"Downloading CIDR list for {code} from {url}")
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            lines = r.text.strip().splitlines()
            logging.info(f"Downloaded {len(lines)} CIDR entries for {code}")
            all_ips.extend(lines)
        except Exception as e:
            logging.warning(f"Failed to download {url}: {e}")

    return all_ips

def read_manual_ips():
    ips = []
    if MANUAL_IPS_FILE.exists():
        logging.info(f"Reading manual IPs from {MANUAL_IPS_FILE}")
        try:
            with MANUAL_IPS_FILE.open() as f:
                for line in f:
                    line = line.strip()
                    if re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', line):
                        ips.append(line)
                    else:
                        logging.debug(f"Ignoring invalid manual IP line: {line}")
            logging.info(f"Read {len(ips)} valid manual IP entries")
        except Exception as e:
            logging.warning(f"Error reading manual IPs: {e}")
    else:
        logging.info("Manual IPs file does not exist, skipping.")
    return ips

def format_ips_yaml_list(ips):
    return [f"    - {ip}\n" for ip in ips]

def update_yaml_with_ips(ips):
    if not ADGUARD_YAML.exists():
        logging.error(f"AdGuardHome.yaml not found at {ADGUARD_YAML}")
        sys.exit(1)

    with ADGUARD_YAML.open() as f:
        lines = f.readlines()

    new_lines = []
    inside_disallowed = False
    ips_inserted = False

    for line in lines:
        stripped = line.rstrip("\n")

        if stripped.startswith("  disallowed_clients:"):
            # Write key line without any value (no [] etc)
            new_lines.append("  disallowed_clients:\n")
            # Insert ips
            if ips:
                new_lines.extend(format_ips_yaml_list(ips))
            # mark inserted
            inside_disallowed = True
            ips_inserted = True
            continue

        if inside_disallowed:
            # skip old IP entries starting with '  - '
            if stripped.startswith("  - "):
                continue
            else:
                inside_disallowed = False

        new_lines.append(line)

    if not ips_inserted:
        # disallowed_clients not found - append at end
        new_lines.append("\n  disallowed_clients:\n")
        if ips:
            new_lines.extend(format_ips_yaml_list(ips))

    with TMP_YAML.open("w") as f:
        f.writelines(new_lines)

    TMP_YAML.replace(ADGUARD_YAML)
    logging.info(f"Updated {ADGUARD_YAML} with {len(ips)} disallowed_clients entries")

def restart_container():
    url = f"{DOCKER_API_URL}/containers/{CONTAINER_NAME}/restart"
    logging.info(f"Restarting container '{CONTAINER_NAME}' via {url}")
    try:
        r = requests.post(url, timeout=10)
        if r.status_code == 204:
            logging.info("Container restarted successfully.")
        else:
            logging.error(f"Failed to restart container. Status: {r.status_code} Response: {r.text}")
    except Exception as e:
        logging.error(f"Exception during container restart: {e}")

def main():
    backup_first_start()
    backup_last_cron()
    cidr_ips = download_cidr_lists(COUNTRIES)
    manual_ips = read_manual_ips()
    combined_ips = cidr_ips + manual_ips
    if not combined_ips:
        logging.warning("No IPs to add to disallowed_clients. The list will be empty.")
    update_yaml_with_ips(combined_ips)
    restart_container()
    logging.info("Blocklist update complete.")

if __name__ == "__main__":
    main()
