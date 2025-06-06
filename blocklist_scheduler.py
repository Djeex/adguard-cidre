#!/usr/bin/env python3
import os
import sys
import logging
import requests
import yaml
import schedule
import time
import re
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='[blocklist] %(levelname)s: %(message)s',
    stream=sys.stdout,
)

ADGUARD_YAML = Path("/adguard/AdGuardHome.yaml")
TMP_YAML = ADGUARD_YAML.parent / (ADGUARD_YAML.name + ".tmp")
MANUAL_IPS_FILE = Path("/adguard/manually_blocked_ips.conf")
CIDR_BASE_URL = "https://raw.githubusercontent.com/vulnebify/cidre/main/output/cidr/ipv4"
COUNTRY_LIST_URL = "https://raw.githubusercontent.com/vulnebify/cidre/refs/heads/main/cidre/countries.py"

FIRST_BACKUP = ADGUARD_YAML.parent / "AdGuardHome.yaml.first-start.bak"
LAST_UPDATE_BACKUP = ADGUARD_YAML.parent / "AdGuardHome.yaml.last-update.bak"

BLOCK_COUNTRIES = os.getenv("BLOCK_COUNTRIES", "")
BLOCKLIST_CRON_TYPE = os.getenv("BLOCKLIST_CRON_TYPE", "daily").lower()
BLOCKLIST_CRON_TIME = os.getenv("BLOCKLIST_CRON_TIME", "06:00")
BLOCKLIST_CRON_DAY = os.getenv("BLOCKLIST_CRON_DAY", "mon").lower()

ADGUARD_CONTAINER_NAME = os.getenv("ADGUARD_CONTAINER_NAME", "adguardhome")
DOCKER_API_URL = os.getenv("DOCKER_API_URL", "http://socket-proxy-adguard:2375")

def backup_first_start():
    if not FIRST_BACKUP.exists():
        logging.info(f"Creating first start backup: {FIRST_BACKUP}")
        FIRST_BACKUP.write_text(ADGUARD_YAML.read_text())
    else:
        logging.info("First start backup already exists, skipping.")

def backup_last_update():
    logging.info(f"Creating last update backup: {LAST_UPDATE_BACKUP}")
    LAST_UPDATE_BACKUP.write_text(ADGUARD_YAML.read_text())

def fetch_all_country_codes():
    try:
        resp = requests.get(COUNTRY_LIST_URL, timeout=15)
        resp.raise_for_status()
        matches = re.findall(r'"([A-Z]{2})"', resp.text)
        return set(code.lower() for code in matches)
    except Exception as e:
        logging.error(f"Failed to fetch available country codes: {e}")
        return set()

def get_selected_countries():
    if not BLOCK_COUNTRIES:
        logging.error("BLOCK_COUNTRIES is not set. Skipping update.")
        return []

    raw_codes = [c.strip() for c in BLOCK_COUNTRIES.split(",") if c.strip()]
    if not raw_codes:
        logging.error("No valid country codes provided.")
        return []

    is_exclusion = all(c.startswith("!") for c in raw_codes)
    is_inclusion = all(not c.startswith("!") for c in raw_codes)

    if not (is_exclusion or is_inclusion):
        logging.error("Mixed syntax in BLOCK_COUNTRIES. Use only inclusion (e.g. 'fr,de') or only exclusion (e.g. '!fr,!de').")
        sys.exit(1)

    available = fetch_all_country_codes()
    selected = {c.lstrip("!") for c in raw_codes}
    unknown = selected - available
    if unknown:
        logging.warning(f"Unknown country codes: {', '.join(sorted(unknown))}")

    if is_exclusion:
        return sorted(available - selected)
    else:
        return sorted(selected & available)

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
                if line and (line.count('.') == 3 or '/' in line):
                    valid_ips.append(line)
        logging.info(f"Added {len(valid_ips)} manual IP entries")
        return valid_ips
    else:
        logging.info("Manual IPs file does not exist, skipping.")
        return []

def update_yaml_with_ips(ips):
    if not ADGUARD_YAML.exists():
        logging.error(f"{ADGUARD_YAML} does not exist. Cannot update.")
        return False

    try:
        with ADGUARD_YAML.open() as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to parse YAML file: {e}")
        return False

    if not isinstance(data, dict):
        logging.error("Invalid YAML format.")
        return False

    data['dns']['disallowed_clients'] = ips

    with TMP_YAML.open('w') as f:
        yaml.safe_dump(data, f)

    TMP_YAML.replace(ADGUARD_YAML)
    logging.info(f"Updated {ADGUARD_YAML} with new disallowed clients list.")
    return True

def restart_adguard_container():
    restart_url = f"{DOCKER_API_URL}/containers/{ADGUARD_CONTAINER_NAME}/restart"
    logging.info(f"Restarting AdGuard container '{ADGUARD_CONTAINER_NAME}'...")
    try:
        resp = requests.post(restart_url, timeout=10)
        if resp.status_code == 204:
            logging.info("AdGuard container restarted successfully.")
        else:
            logging.error(f"Failed to restart container: {resp.status_code} {resp.text}")
    except Exception as e:
        logging.error(f"Error restarting container: {e}")

def update_blocklist():
    countries = get_selected_countries()
    if not countries:
        logging.error("No valid countries to process. Skipping update.")
        return

    cidr_ips = download_cidr_lists(countries)
    manual_ips = read_manual_ips()
    combined_ips = cidr_ips + manual_ips

    backup_last_update()

    success = update_yaml_with_ips(combined_ips)
    if success:
        restart_adguard_container()

def schedule_job():
    try:
        hour, minute = [int(x) for x in BLOCKLIST_CRON_TIME.split(":")]
    except Exception:
        logging.error(f"Invalid BLOCKLIST_CRON_TIME '{BLOCKLIST_CRON_TIME}', must be HH:MM. Defaulting to 06:00.")
        hour, minute = 6, 0

    if BLOCKLIST_CRON_TYPE == "daily":
        schedule.every().day.at(f"{hour:02d}:{minute:02d}").do(update_blocklist)
        logging.info(f"Scheduled daily update at {hour:02d}:{minute:02d}")
    elif BLOCKLIST_CRON_TYPE == "weekly":
        valid_days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        day = BLOCKLIST_CRON_DAY[:3]
        if day not in valid_days:
            logging.error(f"Invalid BLOCKLIST_CRON_DAY '{BLOCKLIST_CRON_DAY}', must be one of {valid_days}. Defaulting to Monday.")
            day = "mon"
        getattr(schedule.every(), day).at(f"{hour:02d}:{minute:02d}").do(update_blocklist)
        logging.info(f"Scheduled weekly update on {day.capitalize()} at {hour:02d}:{minute:02d}")
    else:
        logging.error(f"Invalid BLOCKLIST_CRON_TYPE '{BLOCKLIST_CRON_TYPE}', must be 'daily' or 'weekly'. Defaulting to daily.")
        schedule.every().day.at(f"{hour:02d}:{minute:02d}").do(update_blocklist)
        logging.info(f"Scheduled daily update at {hour:02d}:{minute:02d}")

def main():
    logging.info("Starting blocklist scheduler...")
    backup_first_start()
    update_blocklist()
    schedule_job()
    while True:
        schedule.run_pending()
        time.sleep(10)

if __name__ == "__main__":
    main()
