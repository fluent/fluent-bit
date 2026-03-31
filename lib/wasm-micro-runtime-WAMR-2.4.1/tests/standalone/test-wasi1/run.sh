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

echo "============> compile test-wasi1 to wasm"
/opt/wasi-sdk/bin/clang -O3 -z stack-size=16384 -Wl,--initial-memory=131072 \
    -Wl,--export=main -Wl,--export=__heap_base,--export=__data_end \
    -Wl,--allow-undefined \
    -o test-wasi1.wasm main.c

if [[ $1 != "--aot" ]]; then
    echo "============> run test-wasi1.wasm"
    ${IWASM_CMD} --dir=. --dir=/tmp test-wasi1.wasm test.txt /tmp/somewhere.txt
else
    echo "============> compile test-wasi1.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test-wasi1.aot test-wasi1.wasm \
                        || ${WAMRC_CMD} -o test-wasi1.aot test-wasi1.wasm
    echo "============> run test-wasi1.aot"
    ${IWASM_CMD} --dir=. --dir=/tmp test-wasi1.aot test.txt /tmp/somewhere.txt
fi

