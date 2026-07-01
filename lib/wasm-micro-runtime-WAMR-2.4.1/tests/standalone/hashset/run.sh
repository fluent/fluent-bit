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
    echo "============> run HashSet.wasm"
    ${IWASM_CMD} HashSet.wasm
else
    echo "============> compile HashSet.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o HashSet.aot HashSet.wasm \
                        || ${WAMRC_CMD} -o HashSet.aot HashSet.wasm
    echo "============> run HashSet.aot"
    ${IWASM_CMD} HashSet.aot
fi

