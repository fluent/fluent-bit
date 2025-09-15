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
    echo "============> run c_wasm_simd128_example.wasm"
    ${IWASM_CMD} c_wasm_simd128_example.wasm
else
    echo "============> compile c_wasm_simd128_example.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o c_wasm_simd128_example.aot c_wasm_simd128_example.wasm \
                        || ${WAMRC_CMD} -o c_wasm_simd128_example.aot c_wasm_simd128_example.wasm
    echo "============> run c_wasm_simd128_example.aot"
    ${IWASM_CMD} c_wasm_simd128_example.aot
fi
