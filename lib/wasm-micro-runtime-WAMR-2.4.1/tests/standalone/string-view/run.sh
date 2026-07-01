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
    echo "============> run test_string.wasm"
    ${IWASM_CMD} test_string.wasm
    ${IWASM_CMD} test_string_view.wasm
else
    echo "============> compile test_string.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_string.aot test_string.wasm \
                        || ${WAMRC_CMD} -o test_string.aot test_string.wasm
    echo "============> compile test_string_view.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_string_view.aot test_string_view.wasm \
                        || ${WAMRC_CMD} -o test_string_view.aot test_string_view.wasm
    echo "============> run test_string.aot"
    ${IWASM_CMD} test_string.aot
    echo "============> run test_string_view.aot"
    ${IWASM_CMD} test_string_view.aot
fi

