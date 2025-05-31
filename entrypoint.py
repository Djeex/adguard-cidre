#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='[entrypoint] %(message)s',
    stream=sys.stdout
)

ADGUARD_YAML = Path("/adguard/AdGuardHome.yaml")
FIRST_BACKUP = Path("/adguard/AdGuardHome.yaml.first-start.bak")

def backup_first_start():
    if not FIRST_BACKUP.exists():
        logging.info("Creating first start backup...")
        FIRST_BACKUP.write_text(ADGUARD_YAML.read_text())
    else:
        logging.info("First start backup already exists.")

def run_initial_update():
    logging.info("Running initial update-blocklist.py script...")
    try:
        subprocess.run(
            ["/usr/local/bin/update-blocklist.py"],
            check=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Initial update script failed: {e}")
        sys.exit(1)

def setup_cron():
    cron_expr = os.getenv("BLOCKLIST_CRON", "0 6 * * *")
    cron_line = f"{cron_expr} root /usr/local/bin/update-blocklist.py\n"
    cron_file = "/etc/crontabs/root"
    logging.info(f"Setting cron job: {cron_line.strip()}")
    with open(cron_file, "w") as f:
        f.write(cron_line)

def start_cron_foreground():
    logging.info("Starting cron in foreground...")
    os.execvp("crond", ["crond", "-f"])

def main():
    # Check AdGuardHome.yaml exists
    if not ADGUARD_YAML.exists():
        logging.error(f"{ADGUARD_YAML} not found. Exiting.")
        sys.exit(1)

    backup_first_start()
    run_initial_update()
    setup_cron()
    start_cron_foreground()

if __name__ == "__main__":
    main()
