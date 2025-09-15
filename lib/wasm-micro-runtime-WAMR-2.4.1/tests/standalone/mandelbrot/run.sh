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
    echo "============> run mandel_dd.wasm"
    ${IWASM_CMD} mandel_dd.wasm > image.ppm
else
    echo "============> compile mandel_dd.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o mandel_dd.aot mandel_dd.wasm \
                        || ${WAMRC_CMD} -o mandel_dd.aot mandel_dd.wasm
    echo "============> run mandel_dd.aot"
    ${IWASM_CMD} mandel_dd.aot > image.ppm
fi

