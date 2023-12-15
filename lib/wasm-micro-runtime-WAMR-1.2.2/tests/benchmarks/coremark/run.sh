#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

IWASM="../../../product-mini/platforms/linux/build/iwasm"
WAMRC="../../../wamr-compiler/build/wamrc"

echo "Run coremark with native .."
./coremark.exe

echo "Run coremark with iwasm mode .."
${IWASM} coremark.aot

echo "Run coremakr with iwasm interpreter .."
${IWASM} coremark.wasm
