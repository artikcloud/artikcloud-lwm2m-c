#!/bin/bash

echo "When cross-compiling, do not forget to set CROSS_COMPILE and SYSROOT environment variables"

rm -rf build/
mkdir -p build/package/src/
git archive -o update.tgz HEAD
mv update.tgz build/package/src/
cd build/package/src/
tar -xvf update.tgz
DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -uc -us -aarm64 --target-arch arm64
