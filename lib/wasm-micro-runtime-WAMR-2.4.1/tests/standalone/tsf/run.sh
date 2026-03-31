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
    echo "============> run tsf.wasm"
    if [[ $1 != "--multi-tier-jit" ]]; then
        ${IWASM_CMD} --stack-size=1048576 --dir=. tsf.wasm
    else
        echo "============> run tsf.wasm with fast-jit"
        ${IWASM_CMD} --fast-jit --stack-size=1048576 --dir=. tsf.wasm
        echo "============> run tsf.wasm with llvm-jit"
        ${IWASM_CMD} --llvm-jit --stack-size=1048576 --dir=. tsf.wasm
        echo "============> run tsf.wasm with multi-tier-jit"
        ${IWASM_CMD} --multi-tier-jit --stack-size=1048576 --dir=. tsf.wasm
    fi
else
    echo "============> compile tsf.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o tsf.aot tsf.wasm \
                        || ${WAMRC_CMD} -o tsf.aot tsf.wasm
    echo "============> run tsf.aot"
    ${IWASM_CMD} --stack-size=1048576 --dir=. tsf.aot
fi

