#!/bin/bash
set -e
echo "🔄 Aktualizujem MikroTik Manager..."

# Load Android development environment
if [ -f /etc/profile.d/android-dev.sh ]; then
    source /etc/profile.d/android-dev.sh
fi

# Nastavenie časovej zóny
if [ "$(timedatectl show --property=Timezone --value 2>/dev/null)" != "Europe/Bratislava" ]; then
    echo "🕐 Nastavujem časovú zónu na Europe/Bratislava..."
    timedatectl set-timezone Europe/Bratislava 2>/dev/null || true
fi

systemctl stop mikrotik-manager.service

cd /opt/mikrotik-manager
git fetch origin
git reset --hard origin/main
git clean -fd

source venv/bin/activate
pip install -r requirements.txt
deactivate

# Clear Python cache to ensure fresh code loading
echo "🧹 Čistím Python cache..."
find /opt/mikrotik-manager -name "*.pyc" -delete 2>/dev/null || true
find /opt/mikrotik-manager -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Reload systemd in case service file changed
systemctl daemon-reload

systemctl restart mikrotik-manager.service

echo "✅ Aplikácia bola úspešne aktualizovaná a reštartovaná."
echo "📱 Pre build Android APK: cd /opt/mikrotik-manager && bash build-apk.sh"
