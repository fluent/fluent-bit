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
    echo "============> run nbody.wasm"
    ${IWASM_CMD} nbody.wasm 5000000
else
    echo "============> compile nbody.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o nbody.aot nbody.wasm \
                        || ${WAMRC_CMD} -o nbody.aot nbody.wasm
    echo "============> run nbody.aot"
    ${IWASM_CMD} nbody.aot 50000000
fi

