#!/bin/sh
set -e

if [ -n "$TZ" ]; then
  if [ -f "/usr/share/zoneinfo/$TZ" ]; then
    cp "/usr/share/zoneinfo/$TZ" /etc/localtime
    echo "$TZ" > /etc/timezone
  fi
fi

CRON_EXPR="${BLOCKLIST_CRON:-"0 6 * * *"}"
echo "$CRON_EXPR /usr/local/bin/update-blocklist.sh" > /etc/crontabs/root

exec crond -f -c /etc/crontabs