#!/bin/bash

# Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -eo pipefail
CC="${CC:=/opt/wasi-sdk/bin/clang}"
files=("tcp_udp.c" "nslookup.c")

for file in "${files[@]}"
do
    echo $file
    $CC \
        --target=wasm32-wasi-threads \
        -I../inc \
        ../src/wasi/wasi_socket_ext.c -pthread -ftls-model=local-exec \
        -Wl,--allow-undefined \
        -Wl,--strip-all,--no-entry \
        -Wl,--export=__heap_base \
        -Wl,--export=__data_end \
        -Wl,--shared-memory,--max-memory=10485760 \
        -Wl,--export=malloc \
        -Wl,--export=free \
        -o "${file%.*}.wasm" "$file"
done