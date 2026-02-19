#!/bin/bash
set -euxo pipefail

# Build the module's .so files
cd src
ndk-build
cd ..

# Copy the freshly built shared libraries into Zygisk's expected module structure
cd flashable_module
mkdir -p zygisk
cp ../src/libs/arm64-v8a/libbipan.so zygisk/arm64-v8a.so
cp ../src/libs/armeabi-v7a/libbipan.so zygisk/armeabi-v7a.so

# Create the final flashable zip with no compression
rm -f ../bipan.zip
zip -0 -r ../bipan.zip module.prop service.sh customize.sh zygisk/
