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
    echo "============> run binary_trees.wasm"
    ${IWASM_CMD} binary_trees.wasm 14
else
    echo "============> compile binary_trees.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o binary_trees.aot binary_trees.wasm \
                        || ${WAMRC_CMD} -o binary_trees.aot binary_trees.wasm
    echo "============> run binary_trees.aot"
    ${IWASM_CMD} binary_trees.aot 18
fi

