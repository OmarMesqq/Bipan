#!/bin/bash
set -euxo pipefail

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
