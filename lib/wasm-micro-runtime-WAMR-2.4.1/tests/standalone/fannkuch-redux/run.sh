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
    echo "============> run fannkuch_redux.wasm"
    ${IWASM_CMD} fannkuch_redux.wasm 10
else
    echo "============> compile fannkuch_redux.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o fannkuch_redux.aot fannkuch_redux.wasm \
                        || ${WAMRC_CMD} -o fannkuch_redux.aot fannkuch_redux.wasm
    echo "============> run fannkuch_redux.aot"
    ${IWASM_CMD} fannkuch_redux.aot 11
fi

