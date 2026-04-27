#!/bin/bash
# Bridge Phone - Site Setup Script
# Works on Raspberry Pi (Debian) and Orange Pi Zero 3 (Ubuntu/Armbian)
# Usage: sudo bash rpi_setup.sh <name>.ovpn

set -e

OVPN_FILE="${1:?Usage: $0 <name>.ovpn}"
SITE_NAME="${OVPN_FILE%.ovpn}"
SERVER_IP="207.148.10.72"
DEVICE_BROWSER_PORT=8081

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓  ${NC}$*"; }
info() { echo -e "${CYAN}  →  ${NC}$*"; }
die()  { echo -e "${RED}  ✗  $*${NC}"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0 $1"
[[ -f "$OVPN_FILE" ]] || die "File not found: $OVPN_FILE"

# ── Detect OS and network interface ──────────────────────────────────────────
info "Detecting system..."
if grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    OS="ubuntu"
    PKG_UPDATE="apt-get update -qq"
    PKG_INSTALL="apt-get install -y -qq"
else
    OS="debian"
    PKG_UPDATE="apt-get update -qq"
    PKG_INSTALL="apt-get install -y -qq"
fi

# Detect primary network interface
NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
[[ -z "$NET_IFACE" ]] && NET_IFACE=$(ip link | grep -E "^[0-9]+: (eth|end|enp|ens)" | head -1 | awk '{print $2}' | tr -d ':')
ok "OS: $OS | Network interface: $NET_IFACE"

# ── Install packages ──────────────────────────────────────────────────────────
info "Installing packages..."
$PKG_UPDATE
$PKG_INSTALL openvpn python3 python3-pip python3-venv python3-dev nginx arp-scan sshpass nmap

# Install requests for Python
pip3 install requests --break-system-packages 2>/dev/null || \
    pip3 install requests 2>/dev/null || true
ok "Packages installed"

# ── OpenVPN setup ─────────────────────────────────────────────────────────────
info "Setting up OpenVPN..."
mkdir -p /etc/openvpn/hooks
cp "$OVPN_FILE" "/etc/openvpn/$SITE_NAME.conf"

# VPN up hook — notifies device browser
cat > /etc/openvpn/hooks/vpn-up.sh << EOF
#!/bin/bash
VPN_IP=\$4
sleep 3
curl -s -X POST http://127.0.0.1:$DEVICE_BROWSER_PORT/api/vpn/hook/up \
     -H "Content-Type: application/json" \
     -d "{\"vpn_ip\":\"\$VPN_IP\"}" || true
EOF

# VPN down hook
cat > /etc/openvpn/hooks/vpn-down.sh << EOF
#!/bin/bash
curl -s -X POST http://127.0.0.1:$DEVICE_BROWSER_PORT/api/vpn/hook/down || true
EOF

chmod +x /etc/openvpn/hooks/vpn-up.sh
chmod +x /etc/openvpn/hooks/vpn-down.sh

# Enable and start OpenVPN
systemctl enable openvpn@$SITE_NAME
systemctl start  openvpn@$SITE_NAME
sleep 3
ok "OpenVPN configured for $SITE_NAME"

# ── Device Browser setup ──────────────────────────────────────────────────────
info "Setting up Device Browser..."
mkdir -p /opt/device-browser
python3 -m venv /opt/device-browser/venv
/opt/device-browser/venv/bin/pip install flask requests --quiet
/opt/device-browser/venv/bin/pip install netifaces --quiet 2>/dev/null || apt-get install -y python3-dev && /opt/device-browser/venv/bin/pip install netifaces --quiet

# Download app.py from GitHub
curl -s https://raw.githubusercontent.com/cqsimple/bridge-phone/main/rpi/app.py \
     -o /opt/device-browser/app.py 2>/dev/null || {
    info "GitHub download failed - creating basic app.py"
    # Fallback - basic app that just scans
    cat > /opt/device-browser/app.py << 'PYEOF'
import os
from flask import Flask, jsonify, request
app = Flask(__name__)

@app.route("/api/state")
def state():
    return jsonify({"vpn_up": False, "scanning": False, "devices": [], "last_scan": 0})

@app.route("/api/scan", methods=["POST"])
def scan():
    return jsonify({"status": "started"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8081))
    app.run(host="0.0.0.0", port=port)
PYEOF
}

# Create systemd service for device browser
cat > /etc/systemd/system/device-browser.service << EOF
[Unit]
Description=Site Device Browser
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/device-browser
Environment=PORT=$DEVICE_BROWSER_PORT
ExecStart=/opt/device-browser/venv/bin/python /opt/device-browser/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable device-browser
systemctl start device-browser
sleep 2
ok "Device Browser running on port $DEVICE_BROWSER_PORT"

# ── nginx setup ───────────────────────────────────────────────────────────────
info "Setting up nginx..."
cat > /etc/nginx/sites-available/device-browser << EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass         http://127.0.0.1:$DEVICE_BROWSER_PORT;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_read_timeout 30;
    }

    location ~ ^/device/([0-9.]+)/([0-9]+)(/.*)?$ {
        set \$device_ip   \$1;
        set \$device_port \$2;
        set \$device_path \$3;

        if (\$device_path = "") {
            set \$device_path /;
        }

        proxy_pass              http://\$device_ip:\$device_port\$device_path\$is_args\$args;
        proxy_set_header        Host \$device_ip;
        proxy_set_header        X-Real-IP \$remote_addr;
        proxy_set_header        Authorization \$http_authorization;
        proxy_set_header        Referer "";
        proxy_set_header        Origin "";
        proxy_pass_header       WWW-Authenticate;
        proxy_pass_header       Authorization;
        proxy_redirect          off;
        proxy_read_timeout      300;
        proxy_buffer_size       128k;
        proxy_buffers           4 256k;
        proxy_busy_buffers_size 256k;

        sub_filter_once  off;
        sub_filter_types text/html text/javascript application/javascript;
        sub_filter 'href="/device'   'href="/device';
        sub_filter 'src="/device'    'src="/device';
        sub_filter 'href="/'         'href="/device/\$device_ip/\$device_port/';
        sub_filter "href='/device"   "href='/device";
        sub_filter "href='/"         "href='/device/\$device_ip/\$device_port/";
        sub_filter 'src="/device'    'src="/device';
        sub_filter 'src="/'          'src="/device/\$device_ip/\$device_port/';
        sub_filter "src='/device"    "src='/device";
        sub_filter "src='/"          "src='/device/\$device_ip/\$device_port/";
        sub_filter 'action="/'       'action="/device/\$device_ip/\$device_port/';
    }
}
EOF

ln -sf /etc/nginx/sites-available/device-browser /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
ok "nginx configured"

# ── SSH key setup (for FreePBX access) ───────────────────────────────────────
info "Setting up SSH keys..."
[[ -f /root/.ssh/id_rsa ]] || ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N ""
ok "SSH keys ready"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} Setup Complete!${NC}"
echo -e "  Site name:  $SITE_NAME"
echo -e "  Interface:  $NET_IFACE"
echo -e "  VPN config: /etc/openvpn/$SITE_NAME.conf"
echo ""
echo -e " Waiting for VPN connection..."
for i in {1..12}; do
    VPN_IP=$(ip addr show tun0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    if [[ -n "$VPN_IP" ]]; then
        echo -e "${GREEN}  ✓  VPN connected! IP: $VPN_IP${NC}"
        break
    fi
    sleep 5
    echo -n "."
done
echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
