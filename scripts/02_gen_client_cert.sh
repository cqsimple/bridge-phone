#!/bin/bash
# Usage: bash 02_gen_client_cert.sh <site-name> <server-ip> "Site Label"
set -e

SITE_NAME="${1:?Usage: $0 <site-name> <server-ip> 'Site Label'}"
SERVER_IP="${2:?Usage: $0 <site-name> <server-ip> 'Site Label'}"
SITE_LABEL="${3:-$SITE_NAME}"

EASYRSA="/etc/openvpn/easy-rsa"
CLIENTS="/etc/openvpn/clients"
CCD="/etc/openvpn/ccd"
SITES_FILE="/opt/site-dashboard/sites.json"

echo "Generating certificate for $SITE_NAME..."

# Generate certificate
cd "$EASYRSA"
./easyrsa --batch build-client-full "$SITE_NAME" nopass

# Assign VPN IP based on existing sites
SITE_NUM=$(ls "$CLIENTS" | wc -l)
SITE_NUM=$((SITE_NUM + 1))
# Calculate IP across 10.8.x.x/16 range - supports 65000+ sites
THIRD=$((SITE_NUM / 254))
FOURTH=$(( (SITE_NUM % 254) + 1 ))
VPN_IP="10.8.${THIRD}.${FOURTH}"

# Create client directory
mkdir -p "$CLIENTS/$SITE_NAME"

# Build ovpn file
cat > "$CLIENTS/$SITE_NAME/$SITE_NAME.ovpn" << EOF
client
dev tun
proto udp
remote $SERVER_IP 1194

resolv-retry infinite
connect-retry 5 30
connect-retry-max unlimited

nobind
persist-key
persist-tun
remote-cert-tls server
tls-auth [inline] 1

cipher AES-256-CBC
auth SHA256
compress lz4-v2
keepalive 10 60
verb 3

script-security 2
up   /etc/openvpn/hooks/vpn-up.sh
down /etc/openvpn/hooks/vpn-down.sh

<ca>
$(cat "$EASYRSA/pki/ca.crt")
</ca>
<cert>
$(cat "$EASYRSA/pki/issued/$SITE_NAME.crt")
</cert>
<key>
$(cat "$EASYRSA/pki/private/$SITE_NAME.key")
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF

# Create CCD entry for fixed IP
echo "ifconfig-push $VPN_IP 255.255.0.0" > "$CCD/$SITE_NAME"

# Register in sites.json
python3 << PYEOF
import json
f = "$SITES_FILE"
try:
    sites = json.load(open(f))
except:
    sites = []
if not any(s["name"] == "$SITE_NAME" for s in sites):
    sites.append({"name": "$SITE_NAME", "label": "$SITE_LABEL", "vpn_ip": "$VPN_IP"})
    json.dump(sites, open(f, "w"), indent=2)
    print(f"Registered $SITE_NAME in sites.json with IP $VPN_IP")
else:
    print(f"$SITE_NAME already in sites.json")
PYEOF

echo ""
echo "Done!"
echo "Site:    $SITE_NAME"
echo "Label:   $SITE_LABEL"
echo "VPN IP:  $VPN_IP"
echo "Config:  $CLIENTS/$SITE_NAME/$SITE_NAME.ovpn"
