#!/bin/bash
#
# MikroTik Manager - Android APK Builder
# Builds Android APK from existing Cordova project
#
set -e

# Load Android environment
if [ -f /etc/profile.d/android-dev.sh ]; then
    source /etc/profile.d/android-dev.sh
fi

# Colors for output
function msg_info() { echo -e "\\033[1;34mINFO\\033[0m: $1"; }
function msg_ok() { echo -e "\\033[1;32mSUCCESS\\033[0m: $1"; }
function msg_error() { echo -e "\\033[1;31mERROR\\033[0m: $1"; }

# Check if Cordova project exists
if [ ! -d "/opt/mikrotik-manager-app" ]; then
    msg_error "Cordova projekt neexistuje v /opt/mikrotik-manager-app"
    msg_info "Najprv vytvorte Cordova projekt alebo ho skopírujte do /opt/"
    exit 1
fi

# Check Android development tools
command -v cordova >/dev/null 2>&1 || { msg_error "Cordova nie je nainštalované!"; exit 1; }
command -v gradle >/dev/null 2>&1 || { msg_error "Gradle nie je nainštalované!"; exit 1; }
[ -z "$ANDROID_HOME" ] && { msg_error "ANDROID_HOME nie je nastavené!"; exit 1; }

msg_info "Buildng Android APK..."
cd /opt/mikrotik-manager-app

# Build APK
msg_info "Spúšťam Cordova build pre Android..."
cordova build android

# Copy to main directory
if [ -f "platforms/android/app/build/outputs/apk/debug/app-debug.apk" ]; then
    cp platforms/android/app/build/outputs/apk/debug/app-debug.apk /opt/MikroTikManager.apk
    msg_ok "APK vytvorený: /opt/MikroTikManager.apk"
    ls -lah /opt/MikroTikManager.apk
else
    msg_error "APK súbor nebol vytvorený!"
    exit 1
fi

echo ""
echo "✅ Android APK úspešne vytvorený!"
echo "📱 Súbor: /opt/MikroTikManager.apk"
echo "💾 Veľkosť: $(du -sh /opt/MikroTikManager.apk | cut -f1)"
