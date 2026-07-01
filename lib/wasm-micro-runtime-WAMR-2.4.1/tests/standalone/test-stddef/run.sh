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
    echo "============> run test_stddef_cpp_5_1.wasm"
    ${IWASM_CMD} test_stddef_cpp_5_1.wasm
else
    echo "============> compile test_stddef_cpp_5_1.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_stddef_cpp_5_1.aot test_stddef_cpp_5_1.wasm \
                        || ${WAMRC_CMD} -o test_stddef_cpp_5_1.aot test_stddef_cpp_5_1.wasm
    echo "============> run test_stddef_cpp_5_1.aot"
    ${IWASM_CMD} test_stddef_cpp_5_1.aot
fi
