#!/bin/bash
set -euxo pipefail

rm -rf javac_out
rm -f src/jni/in-app/bipan_java.h
rm -rf src/libs
rm -rf src/obj
rm -f classes.dex
rm -f bipan.zip
rm -rf r8analysis
rm -rf module/zygisk