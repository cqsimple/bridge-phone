# Bridge Phone — VPN Site Browser

Remote device management system using OpenVPN site-to-site tunnels and Raspberry Pi.

## Components
- **server/** — Ubuntu VPS dashboard (Flask)
- **rpi/** — Raspberry Pi Device Browser (Flask + nginx)
- **scripts/** — Setup and management scripts
- **docs/** — Documentation

## Setup
See the user guide in docs/ for full setup instructions.

## Security
Never commit certificates, keys, .ovpn files or the dashboard database.
