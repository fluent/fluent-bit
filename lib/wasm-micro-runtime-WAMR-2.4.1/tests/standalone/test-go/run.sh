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
    echo "============> run test_go.wasm"
    ${IWASM_CMD} test_go.wasm
else
    echo "============> compile test_go.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_go.aot test_go.wasm \
                        || ${WAMRC_CMD} -o test_go.aot test_go.wasm
    echo "============> run test_go.aot"
    ${IWASM_CMD} test_go.aot
fi

