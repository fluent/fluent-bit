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
    echo "============> run smallpt.wasm"
    ${IWASM_CMD} --stack-size=2048000 smallpt.wasm > image.ppm
    echo "============> run smallpt_ex.wasm"
    ${IWASM_CMD} --stack-size=2048000 smallpt_ex.wasm > image.ppm
else
    echo "============> compile smallpt.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o smallpt.aot smallpt.wasm \
                        || ${WAMRC_CMD} -o smallpt.aot smallpt.wasm
    echo "============> run smallpt.aot"
    ${IWASM_CMD} smallpt.aot > image.ppm
    echo "============> compile smallpt_ex.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o smallpt_ex.aot smallpt_ex.wasm \
                        || ${WAMRC_CMD} -o smallpt_ex.aot smallpt_ex.wasm
    echo "============> run smallpt_ex.aot"
    ${IWASM_CMD} smallpt_ex.aot > image.ppm
fi

