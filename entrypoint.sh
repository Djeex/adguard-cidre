#!/bin/sh
set -e

CYAN="\033[1;36m"
NC="\033[0m"

log()  { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }
fail() { echo "$(date '+%Y-%m-%d %H:%M:%S') [!] $*" >&2; exit 1; }

print_banner() {
    version=$(cat VERSION 2>/dev/null || echo "unknown")
    title="AdGuard CIDRe - Version ${version}"
    lines="Source: https://git.djeex.fr/Djeex/adguard-cidre
Mirror: https://github.com/Djeex/adguard-cidre"

    width=${#title}
    old_ifs=$IFS
    IFS='
'
    for l in $lines; do
        [ ${#l} -gt "$width" ] && width=${#l}
    done
    IFS=$old_ifs
    width=$((width + 2))

    border=""
    i=0
    while [ "$i" -lt "$width" ]; do
        border="${border}─"
        i=$((i + 1))
    done
    printf "${CYAN}╭%s╮${NC}\n" "$border"

    total_pad=$((width - ${#title}))
    left=$((total_pad / 2))
    right=$((total_pad - left))
    printf "${CYAN}│${NC}%*s%s%*s${CYAN}│${NC}\n" "$left" "" "$title" "$right" ""

    printf "${CYAN}├%s┤${NC}\n" "$border"

    IFS='
'
    for l in $lines; do
        printf "${CYAN}│${NC} %-*s${CYAN}│${NC}\n" "$((width - 1))" "$l"
    done
    IFS=$old_ifs

    printf "${CYAN}╰%s╯${NC}\n" "$border"
}

print_banner

PUID=${PUID:-911}
PGID=${PGID:-911}

case "$PGID" in
    ''|*[!0-9]*) fail "PGID '$PGID' is not a valid numeric group id." ;;
esac
case "$PUID" in
    ''|*[!0-9]*) fail "PUID '$PUID' is not a valid numeric user id." ;;
esac

[ -d /adguard ] || fail "/adguard is not mounted — check the volume mapping in docker-compose.yml."

log "[i] Requested PUID=$PUID, PGID=$PGID"

log "[~] Checking group for GID $PGID..."
GROUP_NAME=$(getent group "$PGID" | cut -d: -f1 || true)
if [ -z "$GROUP_NAME" ]; then
    log "[→] No existing group with GID $PGID, creating 'appgroup'."
    addgroup -g "$PGID" appgroup || fail "Failed to create group with GID $PGID (addgroup exited $?)."
    GROUP_NAME=appgroup
else
    log "[i] Reusing existing group '$GROUP_NAME' (GID $PGID)."
fi
log "[✓] Group ready: $GROUP_NAME"

log "[~] Checking user for UID $PUID..."
USER_NAME=$(getent passwd "$PUID" | cut -d: -f1 || true)
if [ -z "$USER_NAME" ]; then
    log "[→] No existing user with UID $PUID, creating 'appuser'."
    adduser -D -u "$PUID" -G "$GROUP_NAME" appuser || fail "Failed to create user with UID $PUID (adduser exited $?)."
    USER_NAME=appuser
else
    log "[i] Reusing existing user '$USER_NAME' (UID $PUID)."
fi
log "[✓] User ready: $USER_NAME"

# Grant write access to the shared AdGuard config directory and to the files
# this script manages, without touching anything else AdGuardHome owns in
# there (its own db/certs/stats). AdGuardHome itself runs as root, so this is
# a one-way grant: it keeps full access regardless of what we chown here.
log "[~] Setting ownership of /adguard to $USER_NAME:$GROUP_NAME..."
chown "$USER_NAME:$GROUP_NAME" /adguard || fail "chown on /adguard failed — check that the host directory permissions allow it."
log "[✓] Ownership set on /adguard"

for f in AdGuardHome.yaml AdGuardHome.yaml.first-start.bak AdGuardHome.yaml.last-update.bak AdGuardHome.yaml.tmp; do
    if [ -e "/adguard/$f" ]; then
        chown "$USER_NAME:$GROUP_NAME" "/adguard/$f" || fail "chown on /adguard/$f failed."
        log "[✓] chown OK: /adguard/$f"
    fi
done

log "[→] Dropping privileges to $USER_NAME:$GROUP_NAME and starting blocklist_scheduler.py"
exec su-exec "$USER_NAME:$GROUP_NAME" python3 blocklist_scheduler.py "$@"
