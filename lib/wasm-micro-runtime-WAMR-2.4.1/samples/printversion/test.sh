#! /bin/sh

# Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

DIST=$(mktemp -d)

# WAMR_BUILD_SIMD=0 to avoid fetching simde, which is
# not relevant to this particular test.
cmake -B build-wamr \
-D CMAKE_INSTALL_PREFIX=${DIST} \
-D WAMR_BUILD_SIMD=0 \
../..
cmake --build build-wamr -t install

cmake -B build-app \
-D CMAKE_PREFIX_PATH=${DIST} \
-D CMAKE_INSTALL_PREFIX=${DIST} \
.
cmake --build build-app

./build-app/printversion
