#!/bin/sh

set -e

if [ -n "$TZ" ]; then
  if [ -f "/usr/share/zoneinfo/$TZ" ]; then
    cp "/usr/share/zoneinfo/$TZ" /etc/localtime
    echo "$TZ" > /etc/timezone
  else
    echo "Warning: Timezone file /usr/share/zoneinfo/$TZ not found, skipping timezone setup."
  fi
fi

CRON_EXPR="${BLOCKLIST_CRON:-"0 6 * * *"}" # default: every day at 6:00 am
SCRIPT_PATH="/usr/local/bin/update-blocklist.sh"

echo "Installing cron job with expression: $CRON_EXPR"

echo "$CRON_EXPR root $SCRIPT_PATH" > /etc/crontabs/root

echo "Starting cron..."
exec crond -f -L /dev/stdout
