#!/bin/bash

# Copyright (C) 2023 Amazon Inc.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

WAT2WASM_CMD=$1
WAMRC_CMD=$2
IWASM_CMD=$3

for wat_file in ../../wamr-compiler/*.wat; do
    wasm_file="${wat_file%.wat}.wasm"
    aot_file="${wat_file%.wat}.aot"

    echo "Compiling $wat_file to $wasm_file"
    $WAT2WASM_CMD "$wat_file" -o "$wasm_file"
    echo "Compiling $wasm_file to $aot_file"
    $WAMRC_CMD -o $aot_file $wasm_file
    echo "Testing $aot_file"
    $IWASM_CMD -f _start "$aot_file"
done
