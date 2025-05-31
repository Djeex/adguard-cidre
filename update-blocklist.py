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
                # Simple regex match for IPv4 or IPv4 CIDR
                if line and line.count('.') == 3:
                    valid_ips.append(line)
        logging.info(f"Added {len(valid_ips)} manual IP entries")
        return valid_ips
    else:
        logging.info("Manual IPs file does not exist, skipping.")
        return []

def update_yaml_with_ips(ips):
    # Format IPs for YAML list (4 spaces indent + dash)
    formatted_ips = [f"    - {ip}" for ip in ips]

    inside_disallowed = False
    output_lines = []

    with ADGUARD_YAML.open() as f:
        for line in f:
            if line.strip().startswith("disallowed_clients:"):
                # Replace existing disallowed_clients block
                output_lines.append("disallowed_clients:")
                output_lines.extend(formatted_ips)
                inside_disallowed = True
            elif inside_disallowed:
                # Skip old lines under disallowed_clients (assuming indentation)
                if line.startswith("  ") and not line.startswith("    -"):
                    # This is a new section, disallowed_clients block ended
                    inside_disallowed = False
                    output_lines.append(line.rstrip("\n"))
                # Else skip line inside disallowed_clients block
            else:
                output_lines.append(line.rstrip("\n"))

    # If the file ended while still inside disallowed_clients block, append nothing more (already done)

    # Write to temporary YAML in same folder (to avoid cross-device rename error)
    with TMP_YAML.open("w") as f:
        f.write("\n".join(output_lines) + "\n")

    # Atomic replace
    TMP_YAML.replace(ADGUARD_YAML)
    logging.info(f"Updated {ADGUARD_YAML} with new disallowed clients list.")

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

if __name__ == "__main__":
    main()
