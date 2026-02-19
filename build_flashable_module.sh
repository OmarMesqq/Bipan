#!/bin/bash
set -euxo pipefail

# Build the .so
cd module
ndk-build
cd ..

# Copy built .so into Zygisk module project folder structure
cd flashable_module
rm -f bipan.zip
mkdir -p zygisk
cp ../module/libs/arm64-v8a/libbipan.so zygisk/arm64-v8a.so
cp ../module/libs/armeabi-v7a/libbipan.so zygisk/armeabi-v7a.so

# Create the zip with no compression
zip -0 -r bipan.zip module.prop service.sh zygisk/ targets/
