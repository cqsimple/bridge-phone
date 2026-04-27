#!/bin/bash
# Run this to push latest changes to GitHub
cd /opt/bridge-phone

# Copy latest files from their live locations
cp /opt/site-dashboard/dashboard.py server/
ssh cqsimple@10.8.0.10 "cat /opt/device-browser/app.py" > rpi/app.py
ssh cqsimple@10.8.0.10 "cat /etc/nginx/sites-available/device-browser" > rpi/nginx-device-browser.conf
cp /root/02_gen_client_cert.sh scripts/
cp /root/wireguard/02_add_wg_user.sh scripts/
cp /root/wireguard/03_remove_wg_user.sh scripts/

git add .
git diff --cached --stat
echo ""
read -p "Commit message: " msg
git commit -m "$msg"
git push
echo "Done - pushed to GitHub"
