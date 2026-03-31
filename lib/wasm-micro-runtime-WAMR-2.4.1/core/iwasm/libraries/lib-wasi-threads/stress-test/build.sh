#!/bin/bash

#
# Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

set -eo pipefail
CC=${CC:=/opt/wasi-sdk/bin/clang}
WAMR_DIR=../../../../..

show_usage() {
    echo "Usage: $0 [--sysroot PATH_TO_SYSROOT]"
    echo "--sysroot PATH_TO_SYSROOT specify to build with custom sysroot for wasi-libc"
}

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --sysroot)
            sysroot_path="$2"
            shift
            shift
            ;;
        --help)
            show_usage
            exit
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

rm -rf *.wasm
rm -rf *.aot

for test_c in *.c; do
    test_wasm="$(basename $test_c .c).wasm"

    if [[ -n "$sysroot_path" ]]; then 
        if [ ! -d "$sysroot_path" ]; then 
            echo "Directory $sysroot_path  doesn't exist. Aborting"
            exit 1
        fi
        sysroot_command="--sysroot $sysroot_path"
    fi
    
    echo "Compiling $test_c to $test_wasm"
    $CC \
        -target wasm32-wasi-threads \
        -O2 \
        -Wall \
        -pthread \
        -z stack-size=32768 \
        -Wl,--export=__heap_base \
        -Wl,--export=__data_end \
        -Wl,--shared-memory,--max-memory=1966080 \
        -Wl,--export=wasi_thread_start \
        -Wl,--export=malloc \
        -Wl,--export=free \
        -Wl,--export=test \
        $sysroot_command \
        $test_c -o $test_wasm
done
