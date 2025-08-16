#!/bin/bash
set -e
echo "🔄 Aktualizujem MikroTik Backup Manager..."

# Load Android development environment
if [ -f /etc/profile.d/android-dev.sh ]; then
    source /etc/profile.d/android-dev.sh
fi

systemctl stop mikrotik-manager.service
cd /opt/mikrotik-manager
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
deactivate

# Update Cordova project if it exists
if [ -d "/opt/mikrotik-manager-app" ]; then
    echo "🔄 Aktualizujem Cordova projekt..."
    cd /opt/mikrotik-manager-app
    npm update &>/dev/null || true
    cordova platform update android &>/dev/null || true
fi

systemctl start mikrotik-manager.service
echo "✅ Aplikácia bola úspešne aktualizovaná."
