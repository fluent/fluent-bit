#!/bin/bash

#
# Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

set -eo pipefail
CC=${CC:=/opt/wasi-sdk/bin/clang}
WAMR_DIR=../../../../..

for test_c in *.c; do
    test_wasm="$(basename $test_c .c).wasm"

    if [ $test_wasm = "linear_memory_size_update.wasm" ]; then
        thread_start_file=""
    else
        thread_start_file=$WAMR_DIR/samples/wasi-threads/wasm-apps/wasi_thread_start.S
    fi

    echo "Compiling $test_c to $test_wasm"
    $CC \
        -target wasm32-wasi-threads \
        -pthread -ftls-model=local-exec \
        -z stack-size=32768 \
        -Wl,--export=__heap_base \
        -Wl,--export=__data_end \
        -Wl,--shared-memory,--max-memory=1966080 \
        -Wl,--export=wasi_thread_start \
        -Wl,--export=malloc \
        -Wl,--export=free \
        -I $WAMR_DIR/samples/wasi-threads/wasm-apps \
        $thread_start_file \
        $test_c -o $test_wasm
done