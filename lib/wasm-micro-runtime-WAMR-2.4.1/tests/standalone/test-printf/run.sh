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
    echo "============> run test_printf_builtin.wasm"
    ${IWASM_CMD} test_printf_builtin.wasm > a.log 2>&1
    echo "============> run test_printf_wasi.wasm"
    ${IWASM_CMD} test_printf_wasi.wasm > b.log 2>&1
else
    echo "============> compile test_printf_builtin.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_printf_builtin.aot test_printf_builtin.wasm \
                        || ${WAMRC_CMD} -o test_printf_builtin.aot test_printf_builtin.wasm
    echo "============> run test_printf_builtin.aot"
    ${IWASM_CMD} test_printf_builtin.aot > a.log 2>&1
    echo "============> compile test_printf_wasi.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test_printf_wasi.aot test_printf_wasi.wasm \
                        || ${WAMRC_CMD} -o test_printf_wasi.aot test_printf_wasi.wasm
    echo "============> run test_printf_wasi.aot"
    ${IWASM_CMD} test_printf_wasi.aot > b.log 2>&1
fi

