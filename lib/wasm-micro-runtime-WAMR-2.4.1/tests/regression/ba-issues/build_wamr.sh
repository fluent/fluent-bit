#!/usr/bin/env bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

PLATFORM=$(uname -s | tr A-Z a-z)

readonly WORK_DIR=$PWD
readonly WAMR_DIR=${WORK_DIR}/../../..

function build_wamrc() {
    echo "Build wamrc for spec test under aot compile type"
    cd ${WAMR_DIR}/wamr-compiler &&
    ./build_llvm.sh &&
    cd ${WORK_DIR}/build &&
    if [ -d build-wamrc ]; then rm -rf build-wamrc; else mkdir build-wamrc; fi &&
    cd build-wamrc && cmake ${WAMR_DIR}/wamr-compiler && make -j 4
}

function build_iwasm() {
    echo "Build iwasm with compile flags " $1 " "
    cd ${WAMR_DIR}/product-mini/platforms/${PLATFORM} &&
    cd ${WORK_DIR}/build &&
    if [ -d build-iwasm-$2 ]; then rm -rf build-iwasm-$2; else mkdir build-iwasm-$2; fi &&
    cd build-iwasm-$2 &&
    cmake ${WAMR_DIR}/product-mini/platforms/${PLATFORM} $1 \
          -DCMAKE_BUILD_TYPE=Debug -DWAMR_BUILD_SANITIZER=asan &&
    make -j 4
    if [ "$?" != 0 ]; then
        echo -e "build iwasm failed"
        exit 1
    fi
}

rm -fr build && mkdir build

# build wamrc
build_wamrc

# build default iwasm for testing fast-interp and AOT
build_iwasm "-DWAMR_BUILD_REF_TYPES=1 -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_FAST_INTERP=1" "default"

# build default iwasm for testing fast-interp and AOT with GC enabled
build_iwasm "-DWAMR_BUILD_GC=1 -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_SPEC_TEST=1" "default-gc-enabled"

# build llvm-jit iwasm for testing llvm-jit
build_iwasm "-DWAMR_BUILD_REF_TYPES=1 -DWAMR_BUILD_JIT=1" "llvm-jit"

# build multi-tier-jit iwasm for testing classic-interp, fast-jit, llvm-jit and multi-tier-jit
build_iwasm "-DWAMR_BUILD_REF_TYPES=1 -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1" "multi-tier-jit"

# build default iwasm for testing fast-interp and AOT with libc-wasi disabled
build_iwasm "-DWAMR_BUILD_REF_TYPES=1 -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_LIBC_WASI=0" "default-wasi-disabled"

# build llvm-jit iwasm for testing llvm-jit with libc-wasi disabled
build_iwasm "-DWAMR_BUILD_REF_TYPES=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LIBC_WASI=0" "llvm-jit-wasi-disabled"

# build multi-tier-jit iwasm for testing classic-interp, fast-jit, llvm-jit and multi-tier-jit with libc-wasi disabled
build_iwasm "-DWAMR_BUILD_REF_TYPES=1 -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LIBC_WASI=0" "multi-tier-jit-wasi-disabled"

# TODO: add more version of iwasm, for example, sgx version
