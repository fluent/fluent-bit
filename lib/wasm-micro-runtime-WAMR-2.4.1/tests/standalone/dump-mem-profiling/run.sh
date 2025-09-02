#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

readonly WAMR_DIR="$PWD/../../.."
readonly IWASM_CMD="$PWD/build/iwasm"
readonly WAMRC_CMD="$PWD/../../../wamr-compiler/build/wamrc"

PLATFORM=$(uname -s | tr A-Z a-z)

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
fi

echo "============> test dump-mem-profiling"

rm -fr build && mkdir build && cd build
cmake ${WAMR_DIR}/product-mini/platforms/${PLATFORM} ${CMAKE_FLAGS} \
    -DWAMR_BUILD_DUMP_CALL_STACK=1 -DWAMR_BUILD_MEMORY_PROFILING=1 \
    -DWAMR_BUILD_TARGET=${TARGET}
make -j ${nproc} > /dev/null 2>&1
cd ..

echo "============> compile test-malloc to wasm"
/opt/wasi-sdk/bin/clang -O3 -o test-malloc.wasm wasm-app/main.c \
    -Wl,--export-all -Wl,--export=__heap_base,--export=__data_end

if [[ $1 != "--aot" ]]; then
    echo "============> run test-malloc.wasm"
    ${IWASM_CMD} test-malloc.wasm
else
    echo "============> compile test-malloc.wasm to aot"
    ${WAMRC_CMD} --enable-dump-call-stack -o test-malloc.aot test-malloc.wasm
    echo "============> run test-malloc.aot"
    ${IWASM_CMD} test-malloc.aot
fi
