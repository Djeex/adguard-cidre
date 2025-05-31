#!/usr/bin/env python3
import os
import sys
import logging
import requests
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='[update-blocklist] %(levelname)s: %(message)s',
    stream=sys.stdout,
)

ADGUARD_YAML = Path("/adguard/AdGuardHome.yaml")
FIRST_BACKUP = Path("/adguard/AdGuardHome.yaml.first-start.bak")
LAST_CRON_BACKUP = Path("/adguard/AdGuardHome.yaml.last-cron.bak")
TMP_YAML = ADGUARD_YAML.parent / (ADGUARD_YAML.name + ".tmp")
MANUAL_IPS_FILE = Path("/adguard/manually_blocked_ips.conf")
CIDR_BASE_URL = "https://raw.githubusercontent.com/vulnebify/cidre/main/output/cidr/ipv4"
COUNTRIES = os.getenv("BLOCK_COUNTRIES", "")

def backup_files():
    if not FIRST_BACKUP.exists():
        logging.info(f"Creating first-start backup: {FIRST_BACKUP}")
        FIRST_BACKUP.write_text(ADGUARD_YAML.read_text())
    else:
        logging.info("First-start backup already exists, skipping.")

    logging.info(f"Creating last-cron backup: {LAST_CRON_BACKUP}")
    LAST_CRON_BACKUP.write_text(ADGUARD_YAML.read_text())

def download_cidr_lists(countries):
    combined_ips = []
    for code in countries:
        url = f"{CIDR_BASE_URL}/{code.lower()}.cidr"
        logging.info(f"Downloading CIDR list for {code} from {url}")
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            ips = r.text.strip().splitlines()
            logging.info(f"Downloaded {len(ips)} CIDR entries for {code}")
            combined_ips.extend(ips)
        except Exception as e:
            logging.warning(f"Failed to download {code}: {e}")
    return combined_ips

def read_manual_ips():
    if MANUAL_IPS_FILE.exists():
        logging.info(f"Reading manual IPs from {MANUAL_IPS_FILE}")
        valid_ips = []
        with MANUAL_IPS_FILE.open() as f:
            for line in f:
                line = line.strip()
                # Simple check for IPv4 or IPv4 CIDR format
                if line and line.count('.') == 3:
                    valid_ips.append(line)
        logging.info(f"Added {len(valid_ips)} manual IP entries")
        return valid_ips
    else:
        logging.info("Manual IPs file does not exist, skipping.")
        return []

def update_yaml_with_ips(ips):
    # Read original lines
    with ADGUARD_YAML.open() as f:
        lines = f.readlines()

    output_lines = []
    inside_disallowed = False
    disallowed_indent = ""

    formatted_ips = []  # We'll prepare after knowing indent

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        indent = line[:len(line) - len(stripped)]

        if stripped.startswith("disallowed_clients:"):
            disallowed_indent = indent
            # Write the disallowed_clients line with original indent
            output_lines.append(line.rstrip("\n"))
            inside_disallowed = True

            # Prepare formatted IPs with indentation plus 2 spaces (YAML block indent)
            formatted_ips = [f"{disallowed_indent}  - {ip}" for ip in ips]

            # Immediately add IP list here (replace old block)
            output_lines.extend(formatted_ips)
            continue

        if inside_disallowed:
            # Detect if the current line is out of the disallowed_clients block by checking indentation
            # If line is empty or less indented, disallowed block ended
            if (line.strip() == "") or (len(line) - len(line.lstrip()) <= len(disallowed_indent)):
                inside_disallowed = False
                output_lines.append(line.rstrip("\n"))
            else:
                # Skip lines inside disallowed_clients block (already replaced)
                continue
        else:
            output_lines.append(line.rstrip("\n"))

    # Write to temporary YAML
    with TMP_YAML.open("w") as f:
        f.write("\n".join(output_lines) + "\n")

    TMP_YAML.replace(ADGUARD_YAML)
    logging.info(f"Updated {ADGUARD_YAML} with new disallowed clients list.")


def restart_adguard_container():
    docker_api_url = os.getenv("DOCKER_API_URL", "http://socket-proxy-adguard:2375")
    container_name = os.getenv("ADGUARD_CONTAINER_NAME", "adguardhome")
    restart_url = f"{docker_api_url}/containers/{container_name}/restart"

    logging.info(f"Restarting AdGuard container '{container_name}'...")
    try:
        resp = requests.post(restart_url, timeout=10)
        if resp.status_code == 204:
            logging.info("AdGuard container restarted successfully.")
        else:
            logging.error(f"Failed to restart container: {resp.status_code} {resp.text}")
    except Exception as e:
        logging.error(f"Error restarting container: {e}")

def main():
    if not ADGUARD_YAML.exists():
        logging.error(f"{ADGUARD_YAML} not found, exiting.")
        sys.exit(1)

    if not COUNTRIES:
        logging.error("No countries specified in BLOCK_COUNTRIES environment variable, exiting.")
        sys.exit(1)

    backup_files()

    countries_list = [c.strip() for c in COUNTRIES.split(",") if c.strip()]
    cidr_ips = download_cidr_lists(countries_list)
    manual_ips = read_manual_ips()

    combined_ips = cidr_ips + manual_ips

    update_yaml_with_ips(combined_ips)

    restart_adguard_container()

if __name__ == "__main__":
    main()
