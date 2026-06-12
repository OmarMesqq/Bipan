#!/bin/bash
set -euo pipefail

# Compile the entire BipanJava suite to Java bytecode
javac -cp $ANDROID_HOME/platforms/android-36/android.jar \
  -sourcepath src \
  -d javac_out \
  src/com/omarmesqq/bipan/*.java src/com/omarmesqq/bipan/modules/*.java

# Convert all BipanJava .class into a single .dex
d8 --release \
 --lib $ANDROID_HOME/platforms/android-36/android.jar \
 --output . \
 javac_out/com/omarmesqq/bipan/*.class \
 javac_out/com/omarmesqq/bipan/modules/*.class

# Convert the ART bytecode into an array of bytes C++ can call
xxd -i classes.dex > src/jni/bipan_java.h

# Build the module's .so file
BUILD_MODE="release"
if [[ "${1:-}" == "debug" ]]; then
  BUILD_MODE="debug"
  export BIPAN_DEBUG=1
else
  export BIPAN_DEBUG=0
fi
echo "Building Bipan in $BUILD_MODE mode..."

cd src
ndk-build
cd ..

# Copy the freshly built shared library into Zygisk's expected module structure
cd module
mkdir -p zygisk
cp ../src/libs/arm64-v8a/libbipan.so zygisk/arm64-v8a.so

# Create the final flashable zip with no compression
rm -f ../bipan.zip
zip -0 -r ../bipan.zip module.prop customize.sh zygisk/
