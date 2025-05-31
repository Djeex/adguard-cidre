#!/bin/bash

set -e

ADGUARD_YAML="/adguard/AdGuardHome.yaml"
TMP_YAML="/tmp/AdGuardHome.yaml"
MANUAL_IPS_FILE="/adguard/manually_blocked_ips.conf"
CIDR_BASE_URL="https://raw.githubusercontent.com/vulnebify/cidre/main/output/cidr/ipv4"
COUNTRIES=${BLOCK_COUNTRIES:-""}
DOCKER_API_URL=${DOCKER_API_URL:-"http://socket-proxy-adguard:2375"}
CONTAINER_NAME=${ADGUARD_CONTAINER_NAME:-"adguard-home"}

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

# Format IPs as YAML list items
sed 's/^/    - /' /tmp/cidr/all.txt > /tmp/cidr/ips_formatted.txt

awk '
BEGIN {
  # Read formatted IPs into array
  while ((getline line < "/tmp/cidr/ips_formatted.txt") > 0) {
    ips[++count] = line
  }
  close("/tmp/cidr/ips_formatted.txt")
  inside=0
}

/^  disallowed_clients:/ {
  print
  inside=1
  next
}

/^  [^ ]/ && inside==1 {
  # Insert all IPs here
  for (i=1; i<=count; i++) print ips[i]
  inside=0
}

{
  if (!inside) print
}

END {
  # If file ended while still inside disallowed_clients section
  if (inside==1) {
    for (i=1; i<=count; i++) print ips[i]
  }
}
' "$ADGUARD_YAML" > "$TMP_YAML"

mv "$TMP_YAML" "$ADGUARD_YAML"

echo "Restarting $CONTAINER_NAME container..."
curl -s -X POST "$DOCKER_API_URL/containers/$CONTAINER_NAME/restart" -o /dev/null

echo "Done."
