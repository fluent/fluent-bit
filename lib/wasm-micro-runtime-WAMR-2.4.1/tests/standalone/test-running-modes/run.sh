#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

set -e
if [[ $2 == "--sgx" ]];then
    echo "running modes feature on SGX isn't supported yet, ignored."
    exit 0
else
    readonly IWASM_CMD="$PWD/build/iwasm"
fi

echo "============> test test-running-modes"

./compile_wasm_app.sh

# multi-tier jit
# test iwasm
./build_iwasm.sh "-DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=1"
${IWASM_CMD} --heap-size=16384 wasm-apps/mytest.wasm
${IWASM_CMD} --heap-size=16384 --interp wasm-apps/mytest.wasm
${IWASM_CMD} --heap-size=16384 --fast-jit wasm-apps/mytest.wasm
${IWASM_CMD} --heap-size=16384 --llvm-jit wasm-apps/mytest.wasm
${IWASM_CMD} --heap-size=16384 --llvm-jit --llvm-jit-size-level=1 wasm-apps/mytest.wasm
${IWASM_CMD} --heap-size=16384 --llvm-jit --llvm-jit-size-level=2 --llvm-jit-opt-level=1 wasm-apps/mytest.wasm
${IWASM_CMD} --heap-size=16384 --multi-tier-jit wasm-apps/mytest.wasm

# test c embed api
./build_c_embed.sh "-DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=1"
cd c-embed/build
./c_embed_test --default-running-mode=llvm-jit --module-running-mode=multi-tier-jit
