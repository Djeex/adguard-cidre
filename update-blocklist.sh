#!/bin/bash

set -e

ADGUARD_YAML="/adguard/AdGuardHome.yaml"
TMP_YAML="/tmp/AdGuardHome.yaml"
MANUAL_IPS_FILE="/adguard/manually_blocked_ips.conf"
CIDR_BASE_URL="https://raw.githubusercontent.com/vulnebify/cidre/main/output/cidr/ipv4"
COUNTRIES=${BLOCK_COUNTRIES:-""}
DOCKER_API_URL=${DOCKER_API_URL:-"http://socket-proxy-adguard:2375"}
ADGUARD_CONTAINER_NAME=${ADGUARD_CONTAINER_NAME:-"adguardhome"}

if [ -z "$COUNTRIES" ]; then
  echo "No countries specified in BLOCK_COUNTRIES."
  exit 1
fi

mkdir -p /tmp/cidr
> /tmp/cidr/all.txt

IFS=',' read -ra CODES <<< "$COUNTRIES"
for CODE in "${CODES[@]}"; do
  echo "Downloading CIDR list for $CODE..."
  curl -sf "$CIDR_BASE_URL/${CODE,,}.cidr" -o "/tmp/cidr/${CODE}.cidr" || continue
  cat "/tmp/cidr/${CODE}.cidr" >> /tmp/cidr/all.txt
done

if [ -f "$MANUAL_IPS_FILE" ]; then
  echo "Validating and adding manually blocked IPs from $MANUAL_IPS_FILE..."
  grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' "$MANUAL_IPS_FILE" >> /tmp/cidr/all.txt
fi

IPS_FORMATTED=$(sed 's/^/    - /' /tmp/cidr/all.txt)

awk -v ips="$IPS_FORMATTED" '
BEGIN { inside=0 }
/^  disallowed_clients:/ { print; inside=1; next }
/^  [^ ]/ && inside==1 { print ips; inside=0 }
{ if (!inside) print }
END { if (inside==1) print ips }
' "$ADGUARD_YAML" > "$TMP_YAML"

mv "$TMP_YAML" "$ADGUARD_YAML"

echo "Restarting adguard..."
curl -s -X POST "$DOCKER_API_URL/containers/$ADGUARD_CONTAINER_NAME/restart" -o /dev/null

echo "Done."
