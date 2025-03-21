#!/bin/bash

set -e

cmake \
    -G "MinGW Makefiles" \
    -D CMAKE_INSTALL_PREFIX="$PWD/dest/" \
    -D WITHOUT_WIN32_CONFIG=ON  \
    -D RDKAFKA_BUILD_EXAMPLES=ON \
    -D RDKAFKA_BUILD_TESTS=ON \
    -D RDKAFKA_BUILD_STATIC=OFF \
    -D CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE .

$mingw64 mingw32-make
$mingw64 mingw32-make install

cd tests
cp ../dest/bin/librdkafka.dll ./
cp ../dest/bin/librdkafka++.dll ./
CI=true ./test-runner.exe -l -Q
cd ..
