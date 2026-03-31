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
    echo "============> run test_parson.wasm"
    ${IWASM_CMD} --heap-size=16384 test_parson.wasm
else
    echo "============> compile test_parson.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_parson.aot test_parson.wasm \
                        || ${WAMRC_CMD} -o test_parson.aot test_parson.wasm
    echo "============> run test_parson.aot"
    ${IWASM_CMD} --heap-size=16384 test_parson.aot
fi

