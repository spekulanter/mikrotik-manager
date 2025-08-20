#!/bin/bash
#
# MikroTik Manager - Native Android APK Builder
# Builds Native Android APK with WebView
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

# Check Android development tools
command -v gradle >/dev/null 2>&1 || { msg_error "Gradle nie je nainštalované!"; exit 1; }
[ -z "$ANDROID_HOME" ] && { msg_error "ANDROID_HOME nie je nastavené!"; exit 1; }

# Create Native Android project structure
msg_info "Vytváram Native Android projekt..."
mkdir -p /opt/mikrotik-manager-app
mkdir -p /opt/mikrotik-manager-app/app/src/main/java/com/mikrotik/manager
mkdir -p /opt/mikrotik-manager-app/app/src/main/res/layout
mkdir -p /opt/mikrotik-manager-app/app/src/main/res/values
mkdir -p /opt/mikrotik-manager-app/app/src/main/res/drawable
mkdir -p /opt/mikrotik-manager-app/app/src/main/res/xml

msg_info "Kopírujem template súbory..."
# Copy template files to Native Android project structure
if [ -d "/opt/mikrotik-manager/template" ]; then
    # Copy main Android files
    cp /opt/mikrotik-manager/template/AndroidManifest.xml /opt/mikrotik-manager-app/app/src/main/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/MainActivity.kt /opt/mikrotik-manager-app/app/src/main/java/com/mikrotik/manager/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/SetupActivity.kt /opt/mikrotik-manager-app/app/src/main/java/com/mikrotik/manager/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/activity_main.xml /opt/mikrotik-manager-app/app/src/main/res/layout/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/activity_setup.xml /opt/mikrotik-manager-app/app/src/main/res/layout/ 2>/dev/null || true
    
    # Copy resources
    cp /opt/mikrotik-manager/template/res/values/strings.xml /opt/mikrotik-manager-app/app/src/main/res/values/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/res/values/styles.xml /opt/mikrotik-manager-app/app/src/main/res/values/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/res/drawable/ic_launcher.xml /opt/mikrotik-manager-app/app/src/main/res/drawable/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/res/xml/network_security_config.xml /opt/mikrotik-manager-app/app/src/main/res/xml/ 2>/dev/null || true
    
    # Copy Gradle build files
    cp /opt/mikrotik-manager/template/build.gradle /opt/mikrotik-manager-app/app/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/build.gradle.project /opt/mikrotik-manager-app/build.gradle 2>/dev/null || true
    cp /opt/mikrotik-manager/template/settings.gradle /opt/mikrotik-manager-app/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/gradle.properties /opt/mikrotik-manager-app/ 2>/dev/null || true
    cp /opt/mikrotik-manager/template/gradlew /opt/mikrotik-manager-app/ 2>/dev/null || true
    chmod +x /opt/mikrotik-manager-app/gradlew 2>/dev/null || true
fi

msg_info "Building Native Android APK..."
cd /opt/mikrotik-manager-app

# Build APK using Gradle
msg_info "Spúšťam Gradle build pre Android..."
./gradlew assembleDebug

# Copy to main directory
if [ -f "app/build/outputs/apk/debug/app-debug.apk" ]; then
    cp app/build/outputs/apk/debug/app-debug.apk "/opt/MT Manager.apk"
    msg_ok "APK vytvorený: /opt/MT Manager.apk"
    ls -lah "/opt/MT Manager.apk"
else
    msg_error "APK súbor nebol vytvorený!"
    exit 1
fi

echo ""
echo "✅ Native Android APK úspešne vytvorený!"
echo "📱 Súbor: /opt/MT Manager.apk"
echo "💾 Veľkosť: $(du -sh "/opt/MT Manager.apk" | cut -f1)"
