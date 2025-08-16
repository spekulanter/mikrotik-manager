#!/bin/bash

echo "=== MikroTik Manager - Deploy to Phone ==="
echo ""

APK_PATH="platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk"

if [ ! -f "$APK_PATH" ]; then
    echo "APK not found. Please build it first with:"
    echo "./build-apk.sh"
    echo ""
    exit 1
fi

echo "APK found: $APK_PATH"
echo ""

# Check if adb is available
if ! command -v adb &> /dev/null; then
    echo "ADB not found. Please install Android SDK platform-tools."
    echo ""
    exit 1
fi

# Check if device is connected
DEVICES=$(adb devices | grep -v "List of devices" | grep "device" | wc -l)

if [ $DEVICES -eq 0 ]; then
    echo "No Android device found."
    echo "Please:"
    echo "1. Connect your Android device via USB"
    echo "2. Enable Developer Options"
    echo "3. Enable USB Debugging"
    echo "4. Allow USB debugging on your device"
    echo ""
    exit 1
fi

echo "Found $DEVICES Android device(s)"
echo ""

# Install APK
echo "Installing MikroTik Manager..."
adb install -r "$APK_PATH"

if [ $? -eq 0 ]; then
    echo ""
    echo "=== INSTALLATION SUCCESSFUL ==="
    echo "MikroTik Manager has been installed on your device!"
    echo ""
    echo "You can now:"
    echo "1. Open the app on your phone"
    echo "2. Enter your MikroTik Manager server URL"
    echo "3. Start managing your MikroTik devices!"
else
    echo ""
    echo "=== INSTALLATION FAILED ==="
    echo "Please check the error messages above."
fi
