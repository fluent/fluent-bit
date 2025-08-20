#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

WAMR_DIR=${PWD}/../../..

if [ -z $KW_BUILD ] || [ -z $KW_OUT_FILE ];then
    echo "Local Build Env"
    makewrap="make"
else
    echo "Klocwork Build Env"
    makewrap="kwinject -o $KW_OUT_FILE make"
fi

echo "make Makefile_wasm_app"
$makewrap -f Makefile_wasm_app

echo "make Makefile_wasm_app_no_wasi"
$makewrap -f Makefile_wasm_app_no_wasi

echo "completed."