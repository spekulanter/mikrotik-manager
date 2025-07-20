#!/bin/bash
set -e
echo "🔄 Aktualizujem MikroTik Backup Manager..."
systemctl stop mbm.service
cd /opt/mikrotik-manager
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
deactivate
systemctl start mbm.service
echo "✅ Aplikácia bola úspešne aktualizovaná."
