#!/bin/bash

echo "=== MikroTik Manager APK Builder ==="
echo ""

# Install Java if not present
if ! command -v java &> /dev/null; then
    echo "Installing Java..."
    apt update
    apt install -y openjdk-17-jdk
fi

# Set Java environment
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Install Android SDK if not present
if [ ! -d "$HOME/android-sdk" ]; then
    echo "Installing Android SDK..."
    mkdir -p $HOME/android-sdk
    cd $HOME/android-sdk
    
    # Download command line tools
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
    unzip -q commandlinetools-linux-9477386_latest.zip
    mkdir -p cmdline-tools/latest
    mv cmdline-tools/* cmdline-tools/latest/ 2>/dev/null || true
    
    # Set Android environment
    export ANDROID_HOME=$HOME/android-sdk
    export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools
    
    # Accept licenses and install required packages
    yes | sdkmanager --licenses
    sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"
    
    cd /opt/mikrotik-manager-app
fi

# Set Android environment
export ANDROID_HOME=$HOME/android-sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

echo ""
echo "Building APK..."

# Build the APK
cordova build android --release

if [ $? -eq 0 ]; then
    echo ""
    echo "=== BUILD SUCCESSFUL ==="
    echo "APK location: platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk"
    echo ""
    echo "To install on device:"
    echo "adb install platforms/android/app/build/outputs/apk/release/app-release-unsigned.apk"
else
    echo ""
    echo "=== BUILD FAILED ==="
    echo "Check the error messages above."
fi
