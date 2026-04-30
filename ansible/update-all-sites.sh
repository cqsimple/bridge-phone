#!/bin/bash
# Update all Bridge Phone sites with latest code from GitHub
echo "Updating all Bridge Phone sites..."
ansible-playbook -i /opt/bridge-phone/ansible/inventory.ini \
  /opt/bridge-phone/ansible/update-sites.yml
echo "Done"
