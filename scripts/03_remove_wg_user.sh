#!/bin/bash
# ============================================================
# Remove a WireGuard User
# Usage: sudo bash remove_wg_user.sh <username>
# ============================================================
set -e

USERNAME="${1:?Usage: $0 <username>}"
WG_DIR="/etc/wireguard"
WG_IFACE="wg0"
USERS_FILE="$WG_DIR/users.json"
USER_DIR="$WG_DIR/users/$USERNAME"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓  ${NC}$*"; }
info() { echo -e "${CYAN}  →  ${NC}$*"; }
die()  { echo -e "${RED}  ✗  $*${NC}"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0 $USERNAME"

# Get user's public key from registry
USER_PUBLIC=$(python3 -c "
import json
users = json.load(open('$USERS_FILE'))
for u in users:
    if u['name'] == '$USERNAME':
        print(u['public_key'])
        exit(0)
exit(1)
" 2>/dev/null) || die "User '$USERNAME' not found"

info "Removing $USERNAME (key: ${USER_PUBLIC:0:20}...)"

# ── Remove peer from live WireGuard ───────────────────────────────────────────
wg set $WG_IFACE peer "$USER_PUBLIC" remove 2>/dev/null && ok "Peer removed from live WireGuard" || true

# ── Remove [Peer] block from wg0.conf ─────────────────────────────────────────
python3 << EOF
lines = open("/etc/wireguard/$WG_IFACE.conf").readlines()
out = []
skip = False
for line in lines:
    if line.strip() == "[Peer]":
        # Look ahead to see if this is the target user
        skip = False
    if f"# $USERNAME" in line:
        # Remove the [Peer] line we just added
        if out and out[-1].strip() == "[Peer]":
            out.pop()
        skip = True
        continue
    if skip and line.strip().startswith("[") and line.strip() != "[Peer]":
        skip = False
    if not skip:
        out.append(line)

open("/etc/wireguard/$WG_IFACE.conf", "w").writelines(out)
print("Config updated")
EOF

# Reload WireGuard
wg syncconf $WG_IFACE <(wg-quick strip $WG_IFACE)
ok "WireGuard reloaded"

# ── Remove user directory ──────────────────────────────────────────────────────
[[ -d "$USER_DIR" ]] && rm -rf "$USER_DIR" && ok "User files deleted"

# ── Update registry ────────────────────────────────────────────────────────────
python3 << EOF
import json
users = json.load(open("$USERS_FILE"))
users = [u for u in users if u["name"] != "$USERNAME"]
json.dump(users, open("$USERS_FILE", "w"), indent=2)
print("Registry updated")
EOF

echo ""
echo -e "${BOLD}${GREEN} User '$USERNAME' removed successfully.${NC}"
echo "  Their VPN access is revoked immediately."
echo "  Their .conf file and keys have been deleted."
