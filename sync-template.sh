#!/bin/bash
#
# MikroTik Manager - Template Sync
# Kopíruje zmeny z Cordova projektu späť do template adresára
#
set -e

# Colors for output
function msg_info() { echo -e "\\033[1;34mINFO\\033[0m: $1"; }
function msg_ok() { echo -e "\\033[1;32mSUCCESS\\033[0m: $1"; }
function msg_error() { echo -e "\\033[1;31mERROR\\033[0m: $1"; }

# Check if Cordova project exists
if [ ! -d "/opt/mikrotik-manager-app" ]; then
    msg_error "Cordova projekt neexistuje v /opt/mikrotik-manager-app"
    exit 1
fi

# Check if template directory exists
if [ ! -d "/opt/mikrotik-manager/template" ]; then
    msg_error "Template adresár neexistuje v /opt/mikrotik-manager/template"
    exit 1
fi

msg_info "Kopírujem zmeny z Cordova projektu do template..."

# Kopíruj www súbory
if [ -f "/opt/mikrotik-manager-app/www/index.html" ]; then
    cp /opt/mikrotik-manager-app/www/index.html /opt/mikrotik-manager/template/
    msg_ok "index.html skopírované"
fi

# Kopíruj config.xml
if [ -f "/opt/mikrotik-manager-app/config.xml" ]; then
    cp /opt/mikrotik-manager-app/config.xml /opt/mikrotik-manager/template/
    msg_ok "config.xml skopírované"
fi

# Kopíruj resources (iba ak existujú súbory)
if [ -d "/opt/mikrotik-manager-app/res" ]; then
    # Vytvor template/res adresár ak neexistuje
    mkdir -p /opt/mikrotik-manager/template/res
    
    # Kopíruj len ak existujú súbory
    if [ "$(find /opt/mikrotik-manager-app/res -type f | wc -l)" -gt 0 ]; then
        cp -r /opt/mikrotik-manager-app/res/* /opt/mikrotik-manager/template/res/ 2>/dev/null || true
        msg_ok "Resource súbory skopírované"
    else
        msg_info "Žiadne resource súbory na kopírovanie"
    fi
fi

echo ""
echo "✅ Template synchronizácia dokončená!"
echo "📝 Nezabudni commitnúť zmeny do Git repozitára:"
echo "   cd /opt/mikrotik-manager"
echo "   git add template/"
echo "   git commit -m \"Update template files\""
echo "   git push origin main"
