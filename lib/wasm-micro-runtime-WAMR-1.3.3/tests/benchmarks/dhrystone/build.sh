#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

PLATFORM=$(uname -s | tr A-Z a-z)

WAMRC_CMD=$PWD/../../../wamr-compiler/build/wamrc

echo "===> compile dhrystone src to dhrystone_native"
gcc -O3 -o dhrystone_native src/dhry_1.c src/dhry_2.c -I include

echo "===> compile dhrystone src to dhrystone.wasm"
/opt/wasi-sdk/bin/clang -O3 \
    -o dhrystone.wasm src/dhry_1.c src/dhry_2.c -I include \
    -Wl,--export=__heap_base -Wl,--export=__data_end

echo "===> compile dhrystone.wasm to dhrystone.aot"
${WAMRC_CMD} -o dhrystone.aot dhrystone.wasm

if [[ ${PLATFORM} == "linux" ]]; then
    echo "===> compile dhrystone.wasm to dhrystone_segue.aot"
    ${WAMRC_CMD} --enable-segue -o dhrystone_segue.aot dhrystone.wasm
fi
