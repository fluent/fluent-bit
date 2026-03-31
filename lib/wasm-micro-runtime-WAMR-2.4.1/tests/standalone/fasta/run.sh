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
    echo "============> run fasta.wasm"
    ${IWASM_CMD} fasta.wasm 1000000 > image.ppm
else
    echo "============> compile fasta.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o fasta.aot fasta.wasm \
                        || ${WAMRC_CMD} -o fasta.aot fasta.wasm
    echo "============> run fasta.aot"
    ${IWASM_CMD} fasta.aot 10000000 > image.ppm
fi

