#!/bin/bash
#
# Quick fix - install Android build-tools 34.0.0 required by Cordova
#

echo "🔧 Inštalujem Android build-tools 34.0.0..."

# Set Android environment
export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools

# Install missing build-tools
if [ -d "/opt/android-sdk/cmdline-tools/latest/bin" ]; then
    /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager "build-tools;34.0.0"
    echo "✅ Android build-tools 34.0.0 nainštalované!"
    echo "🚀 Teraz môžeš spustiť: ./build-apk.sh"
else
    echo "❌ Android SDK nie je správne nainštalované!"
    exit 1
fi
