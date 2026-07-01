#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

if [[ $2 == "--sgx" ]];then
    readonly IWASM_CMD="../../../product-mini/platforms/linux-sgx/enclave-sample/iwasm"
else
    readonly IWASM_CMD="../../../product-mini/platforms/linux/build/iwasm"
fi
readonly WAMRC_CMD="../../../wamr-compiler/build/wamrc"

if [[ $1 != "--aot" ]]; then
    echo "============> run test_aes.wasm"
    if [[ $1 != "--multi-tier-jit" ]]; then
        ${IWASM_CMD} --heap-size=16384 test_aes.wasm
    else
        echo "============> run test_aes.wasm with interp"
        ${IWASM_CMD} --heap-size=16384 --interp test_aes.wasm
        echo "============> run test_aes.wasm with fast-jit"
        ${IWASM_CMD} --heap-size=16384 --fast-jit test_aes.wasm
        echo "============> run test_aes.wasm with llvm-jit"
        ${IWASM_CMD} --heap-size=16384 --llvm-jit test_aes.wasm
        echo "============> run test_aes.wasm with multi-tier-jit"
        ${IWASM_CMD} --heap-size=16384 --multi-tier-jit test_aes.wasm
    fi
else
    echo "============> compile test_aes.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_aes.aot test_aes.wasm \
                        || ${WAMRC_CMD} -o test_aes.aot test_aes.wasm
    echo "============> run test_aes.aot"
    ${IWASM_CMD} --heap-size=16384 test_aes.aot
fi

