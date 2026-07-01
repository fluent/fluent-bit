#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

# Download alice29.txt
wget https://raw.githubusercontent.com/google/brotli/master/tests/testdata/alice29.txt

if [[ $2 == "--sgx" ]];then
    readonly IWASM_CMD="../../../product-mini/platforms/linux-sgx/enclave-sample/iwasm"
else
    readonly IWASM_CMD="../../../product-mini/platforms/linux/build/iwasm"
fi
readonly WAMRC_CMD="../../../wamr-compiler/build/wamrc"

if [[ $1 != "--aot" ]]; then
    echo "============> run brotli.wasm"
    cat alice29.txt | ${IWASM_CMD} brotli.wasm -c > alice29.txt.comp
else
    echo "============> compile brotli.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o brotli.aot brotli.wasm \
                        || ${WAMRC_CMD} -o brotli.aot brotli.wasm
    echo "============> run brotli.aot"
    cat alice29.txt | ${IWASM_CMD} brotli.aot -c > alice29.txt.comp
fi

