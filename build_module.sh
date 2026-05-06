#!/bin/bash
set -euxo pipefail

# Compile the SettingsHook Java code
javac -cp $ANDROID_HOME/platforms/android-36/android.jar src/com/omarmesqq/bipan/SettingsHook.java

# Convert Java bytecode (.class) to ART's/Dalvik's bytecode (.dex)
d8 --release --lib $ANDROID_HOME/platforms/android-36/android.jar src/com/omarmesqq/bipan/SettingsHook.class

# Transform it into an array of bytes C++ can call
xxd -i classes.dex > src/jni/settings_hook_payload.h

# Build the module's .so file
cd src
ndk-build
cd ..

# Copy the freshly built shared library into Zygisk's expected module structure
cd module
mkdir -p zygisk
cp ../src/libs/arm64-v8a/libbipan.so zygisk/arm64-v8a.so

# Create the final flashable zip with no compression
rm -f ../bipan.zip
zip -0 -r ../bipan.zip module.prop service.sh customize.sh zygisk/
