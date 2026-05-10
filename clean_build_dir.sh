#!/bin/bash
set -euxo pipefail

rm -rf javac_out
rm -f src/jni/bipan_java.h
rm -rf src/jni/libs
rm -rf src/jni/obj
rm -f classes.dex
rm -f bipan.zip

rm -rf module/zygisk