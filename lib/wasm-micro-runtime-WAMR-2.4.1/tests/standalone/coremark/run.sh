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
    echo "============> run coremark_wasi_nofp.wasm"
    ${IWASM_CMD} coremark_wasi_nofp.wasm
    echo "============> run coremark_wasi.wasm"
    ${IWASM_CMD} coremark_wasi.wasm
else
    echo "============> compile coremark_wasi_nofp.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o coremark_wasi_nofp.aot coremark_wasi_nofp.wasm \
                        || ${WAMRC_CMD} -o coremark_wasi_nofp.aot coremark_wasi_nofp.wasm
    echo "============> run coremark_wasi_nofp.aot"
    ${IWASM_CMD} coremark_wasi_nofp.aot

    echo "============> compile coremark_wasi.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o coremark_wasi.aot coremark_wasi.wasm \
                        || ${WAMRC_CMD} -o coremark_wasi.aot coremark_wasi.wasm
    echo "============> run coremark_wasi.aot"
    ${IWASM_CMD} coremark_wasi.aot
fi

