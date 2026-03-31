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
    echo "============> run gcc_loops.wasm"
    ${IWASM_CMD} gcc_loops.wasm 1
else
    echo "============> compile gcc_loops.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o gcc_loops.aot gcc_loops.wasm \
                        || ${WAMRC_CMD} -o gcc_loops.aot gcc_loops.wasm
    echo "============> run gcc_loops.aot"
    ${IWASM_CMD} gcc_loops.aot 1
fi

