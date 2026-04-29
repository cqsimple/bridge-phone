#!/bin/bash
# ============================================================
# Add a WireGuard User
# Run on the Ubuntu server after 01_setup_wireguard.sh
#
# Usage:
#   sudo bash add_wg_user.sh <username>
#   sudo bash add_wg_user.sh alice
#   sudo bash add_wg_user.sh "bob"
#
# What this does:
#   1. Generates a keypair for the user
#   2. Assigns them the next available IP (10.9.0.2, .3, .4...)
#   3. Adds their [Peer] block to wg0.conf
#   4. Hot-reloads WireGuard (no downtime for existing users)
#   5. Writes their .conf file to /etc/wireguard/users/<name>/
#   6. Prints a QR code for mobile device setup
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
[[ -f "$WG_DIR/server_info" ]] || die "Run 01_setup_wireguard.sh first"

source "$WG_DIR/server_info"

# Check user doesn't already exist
if python3 -c "
import json
users = json.load(open('$USERS_FILE'))
names = [u['name'] for u in users]
exit(0 if '$USERNAME' not in names else 1)
" 2>/dev/null; then
    : # user doesn't exist, continue
else
    die "User '$USERNAME' already exists. Use remove_wg_user.sh to remove first."
fi

# ── Assign next available IP ───────────────────────────────────────────────────
info "Assigning IP address..."
NEXT_IP=$(python3 << 'EOF'
import json

users_file = "/etc/wireguard/users.json"
try:
    users = json.load(open(users_file))
except:
    users = []

# Find highest used last octet
used = set()
for u in users:
    try:
        last = int(u["ip"].split(".")[-1])
        used.add(last)
    except:
        pass

# Start from .2 (.1 is the server)
next_num = 2
while next_num in used:
    next_num += 1

if next_num > 65534:
    print("ERROR: No IPs available")
    exit(1)

third  = next_num // 254
fourth = (next_num % 254) + 1
print(f"10.9.{third}.{fourth}")
EOF
)

[[ "$NEXT_IP" == ERROR* ]] && die "$NEXT_IP"
ok "Assigned IP: $NEXT_IP"

# ── Generate user keys ─────────────────────────────────────────────────────────
info "Generating keys for $USERNAME..."
mkdir -p "$USER_DIR"
chmod 700 "$USER_DIR"

wg genkey | tee "$USER_DIR/private.key" | wg pubkey > "$USER_DIR/public.key"
chmod 600 "$USER_DIR/private.key"

USER_PRIVATE=$(cat "$USER_DIR/private.key")
USER_PUBLIC=$(cat  "$USER_DIR/public.key")
ok "Keys generated"

# ── Write user .conf file ──────────────────────────────────────────────────────
info "Writing user config..."
cat > "$USER_DIR/$USERNAME.conf" <<EOF
[Interface]
PrivateKey = $USER_PRIVATE
Address    = $NEXT_IP/32
DNS        = 1.1.1.1

[Peer]
PublicKey  = $SERVER_PUBLIC
Endpoint   = $SERVER_PUBIP:$WG_PORT

# AllowedIPs controls what traffic goes through the VPN tunnel:
#   10.9.0.1    = dashboard server
#   10.8.0.0/24 = RPi site VPN subnet (to reach device browsers directly if needed)
# All other traffic (browsing etc) goes through normal internet connection.
AllowedIPs = 10.9.0.1/32, 10.8.0.0/24

# Keep connection alive through NAT
PersistentKeepalive = 25
EOF
chmod 600 "$USER_DIR/$USERNAME.conf"
ok "Config written: $USER_DIR/$USERNAME.conf"

# ── Add peer to server config ──────────────────────────────────────────────────
info "Adding peer to WireGuard server..."
cat >> "$WG_DIR/$WG_IFACE.conf" <<EOF

[Peer]
# $USERNAME — $NEXT_IP
PublicKey  = $USER_PUBLIC
AllowedIPs = $NEXT_IP/32
EOF

# Hot-reload WireGuard (adds new peer without dropping existing connections)
wg syncconf $WG_IFACE <(wg-quick strip $WG_IFACE)
ok "Peer added and WireGuard reloaded (no downtime)"

# ── Update users registry ──────────────────────────────────────────────────────
python3 << EOF
import json, datetime

users_file = "$USERS_FILE"
try:
    users = json.load(open(users_file))
except:
    users = []

users.append({
    "name":       "$USERNAME",
    "ip":         "$NEXT_IP",
    "public_key": "$USER_PUBLIC",
    "created":    datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
})

json.dump(users, open(users_file, "w"), indent=2)
print("Registry updated")
EOF

# ── Print QR code for mobile setup ────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} User Added: $USERNAME${NC}"
echo -e "  VPN IP:     $NEXT_IP"
echo -e "  Public key: $USER_PUBLIC"
echo -e "  Config:     $USER_DIR/$USERNAME.conf"
echo ""
echo -e "${BOLD} QR Code for WireGuard mobile app:${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
qrencode -t ansiutf8 < "$USER_DIR/$USERNAME.conf"
echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD} To install on a device:${NC}"
echo "  Mobile:  Scan the QR code above with the WireGuard app"
echo "  Desktop: Copy $USER_DIR/$USERNAME.conf to the device"
echo "           Import it in the WireGuard app"
echo ""
echo -e "${BOLD} After connecting, access dashboard at:${NC}"
echo -e "  ${GREEN}http://10.9.0.1:8080${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
