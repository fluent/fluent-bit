#! /bin/sh

# Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

PREFIX=${1:-/tmp/wamr}
WASI_SDK=${WASI_SDK:-/opt/wasi-sdk}

cmake -B build-app-nn \
-DCMAKE_TOOLCHAIN_FILE=${WASI_SDK}/share/cmake/wasi-sdk.cmake \
-DCMAKE_PREFIX_PATH=${PREFIX} \
samples/nn
cmake --build build-app-nn

cmake -B build-app-nn-cli \
-DCMAKE_TOOLCHAIN_FILE=${WASI_SDK}/share/cmake/wasi-sdk.cmake \
-DCMAKE_PREFIX_PATH=${PREFIX} \
samples/nn-cli
cmake --build build-app-nn-cli

cmake -B build-app-socket-nslookup \
-DCMAKE_TOOLCHAIN_FILE=${WASI_SDK}/share/cmake/wasi-sdk-pthread.cmake \
-DCMAKE_PREFIX_PATH=${PREFIX} \
samples/socket-nslookup
cmake --build build-app-socket-nslookup

cmake -B build-app-socket-tcp-udp \
-DCMAKE_TOOLCHAIN_FILE=${WASI_SDK}/share/cmake/wasi-sdk-pthread.cmake \
-DCMAKE_PREFIX_PATH=${PREFIX} \
samples/socket-tcp-udp
cmake --build build-app-socket-tcp-udp
