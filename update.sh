#!/bin/bash
cd /root/vpn_bot
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart vpn_bot
