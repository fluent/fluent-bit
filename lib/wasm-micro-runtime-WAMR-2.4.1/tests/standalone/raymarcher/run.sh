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
    echo "============> run raymarcher.wasm"
    ${IWASM_CMD} raymarcher.wasm > a.log 2>&1
else
    echo "============> compile raymarcher.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o raymarcher.aot raymarcher.wasm \
                        || ${WAMRC_CMD} -o raymarcher.aot raymarcher.wasm
    echo "============> run raymarcher.aot"
    ${IWASM_CMD} raymarcher.aot > a.log 2>&1
fi
