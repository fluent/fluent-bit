#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

if [[ $1 == "--classic-interp" ]]; then
    CMAKE_FLAGS="-DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=0"
elif [[ $1 == "--fast-interp" ]]; then
    CMAKE_FLAGS="-DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=1"
elif [[ $1 == "--fast-jit" ]]; then
    CMAKE_FLAGS="-DWAMR_BUILD_FAST_JIT=1"
elif [[ $1 == "--jit" ]]; then
    CMAKE_FLAGS="-DWAMR_BUILD_JIT=1"
elif [[ $1 == "--multi-tier-jit" ]]; then
    CMAKE_FLAGS="-DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1"
fi

TARGET="X86_64"
if [[ $3 = "X86_32" ]]; then
    TARGET="X86_32"
    WAMRC_FLAGS="--target=i386"
fi

readonly WAMRC_CMD="$PWD/../../../wamr-compiler/build/wamrc"

echo "============> test test-module-malloc"

if [[ $1 != "--aot" ]]; then
    rm -fr build && mkdir build && cd build
    cmake .. -DWAMR_BUILD_TARGET=${TARGET}
    make -j > /dev/null 2>&1
    ./iwasm --native-lib=./libtest_module_malloc.so wasm-app/test.wasm
    if [ ${TARGET} == "X86_64" ]; then
        echo "============> test test-module-malloc with hw bound check disabled"
        cd .. && rm -fr build && mkdir build && cd build
        cmake .. -DWAMR_BUILD_TARGET=${TARGET} -DWAMR_DISABLE_HW_BOUND_CHECK=1
        make clean
        make -j > /dev/null 2>&1
        ./iwasm --native-lib=./libtest_module_malloc.so wasm-app/test.wasm
    fi
else
    rm -fr build && mkdir build && cd build
    cmake .. -DWAMR_BUILD_TARGET=${TARGET}
    make -j > /dev/null 2>&1
    ${WAMRC_CMD} ${WAMRC_FLAGS} -o wasm-app/test.aot wasm-app/test.wasm
    ./iwasm --native-lib=./libtest_module_malloc.so wasm-app/test.aot
    if [ ${TARGET} == "X86_64" ]; then
        echo "============> test test-module-malloc with hw bound check disabled"
        cd .. && rm -fr build && mkdir build && cd build
        cmake .. -DWAMR_BUILD_TARGET=${TARGET} -DWAMR_DISABLE_HW_BOUND_CHECK=1
        make clean
        make -j > /dev/null 2>&1
        ${WAMRC_CMD} ${WAMRC_FLAGS} --bounds-checks=1 -o wasm-app/test.aot wasm-app/test.wasm
        ./iwasm --native-lib=./libtest_module_malloc.so wasm-app/test.aot
    fi
fi
