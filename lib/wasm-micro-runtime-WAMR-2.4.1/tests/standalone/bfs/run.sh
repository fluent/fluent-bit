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
    echo "============> run bfs.wasm"
    ${IWASM_CMD} --heap-size=0 -f bfs bfs.wasm
else
    echo "============> compile bfs.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o bfs.aot bfs.wasm \
                        || ${WAMRC_CMD} -o bfs.aot bfs.wasm
    echo "============> run bfs.aot"
    ${IWASM_CMD} --heap-size=0 -f bfs bfs.aot
fi

