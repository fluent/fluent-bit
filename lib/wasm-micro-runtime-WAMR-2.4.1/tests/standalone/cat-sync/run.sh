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

dd if=/dev/urandom of=./random bs=4k count=1k

if [[ $1 != "--aot" ]]; then
    echo "============> run cat_sync.wasm"
    ${IWASM_CMD} cat_sync.wasm 0 < ./random > image.ppm
else
    echo "============> compile cat_sync.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o cat_sync.aot cat_sync.wasm \
                        || ${WAMRC_CMD} -o cat_sync.aot cat_sync.wasm
    echo "============> run cat_sync.aot"
    ${IWASM_CMD} cat_sync.aot 0 < ./random > image.ppm
fi

