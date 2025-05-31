#!/bin/sh

set -e

CRON_EXPR="${BLOCKLIST_CRON:-"0 6 * * *"}" # default: every hour
SCRIPT_PATH="/usr/local/bin/update-blocklist.sh"

echo "Installing cron job with expression: $CRON_EXPR"

echo "$CRON_EXPR root $SCRIPT_PATH" > /etc/crontabs/root

echo "Starting cron..."
crond -f -L /dev/stdout
