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

echo "============> compile test-strchr to wasm"
/opt/wasi-sdk/bin/clang -O3 -z stack-size=4096 -Wl,--initial-memory=65536 \
    -Wl,--export=main -Wl,--export=__main_argc_argv \
    -o test-strchr.wasm main.c \
    -Wl,--export=__heap_base,--export=__data_end -Wl,--no-entry \
    -nostdlib -Wl,--allow-undefined

if [[ $1 != "--aot" ]]; then
    echo "============> run test-strchr.wasm"
    ${IWASM_CMD} --heap-size=16384 test-strchr.wasm
else
    echo "============> compile test-strchr.wasm to aot"
    [[ $2 == "--sgx" ]] && ${WAMRC_CMD} -sgx -o test-strchr.aot test-strchr.wasm \
                        || ${WAMRC_CMD} -o test-strchr.aot test-strchr.wasm
    echo "============> run test-strchr.aot"
    ${IWASM_CMD} --heap-size=16384 test-strchr.aot
fi

