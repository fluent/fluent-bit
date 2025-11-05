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
    echo "============> run dhrystone.wasm"
    ${IWASM_CMD} --heap-size=16384 dhrystone.wasm
else
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o dhrystone.aot dhrystone.wasm \
                        || ${WAMRC_CMD} -o dhrystone.aot dhrystone.wasm
    echo "============> run dhrystone.aot"
    ${IWASM_CMD} --heap-size=16384 dhrystone.aot
fi
