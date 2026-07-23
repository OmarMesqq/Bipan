#!/bin/bash
set -euo pipefail

# Compile the entire BipanJava suite to Java bytecode
javac -cp $ANDROID_HOME/platforms/android-36/android.jar \
  -sourcepath src \
  -d javac_out \
  src/b/*.java \
  src/b/**/*.java

# Shrink, obfuscate, and minify all BipanJava.class into DEX
mkdir -p ./r8analysis
java -cp r8lib.jar \
  -Dcom.android.tools.r8.dumpkeepradiushtmltodirectory=./r8analysis \
  com.android.tools.r8.R8 \
  --release \
  --lib $ANDROID_HOME/platforms/android-36/android.jar \
  --pg-conf bipan-rules.pro \
  --output . \
  $(find javac_out -name '*.class' | tr '\n' ' ')

# Convert the ART bytecode into an array of bytes C++ can call
xxd -i classes.dex > src/jni/in-app/bipan_java.h

# Build the module's .so file
BUILD_MODE="release"
if [[ "${1:-}" == "debug" ]]; then
  BUILD_MODE="debug"
  export BIPAN_DEBUG=1
else
  export BIPAN_DEBUG=0
fi
echo "Building Bipan in $BUILD_MODE mode..."
echo ""

cd src
ndk-build
cd ..

# Copy the freshly built shared library into Zygisk's expected module structure
cd module
mkdir -p zygisk
cp ../src/libs/arm64-v8a/libbipan.so zygisk/arm64-v8a.so

if [[ "${1:-}" == "debug" ]]; then
  echo ""
  echo "Skipping symbol stripping"
else
  if [[ "$(uname -s)" == "Darwin" ]]; then
    $NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-objcopy \
      --strip-all \
      -R .eh_frame \
      -R .eh_frame_hdr \
      -R .gcc_except_table \
      -R .note.gnu.build-id \
      -R .note.android.ident \
      ./zygisk/arm64-v8a.so
  else
    $NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy \
      --strip-all \
      -R .eh_frame \
      -R .eh_frame_hdr \
      -R .gcc_except_table \
      -R .note.gnu.build-id \
      -R .note.android.ident \
      ./zygisk/arm64-v8a.so
  fi
fi

echo ""
# Create the final flashable zip with no compression
rm -f ../bipan.zip
zip -0 -r ../bipan.zip module.prop customize.sh zygisk/
