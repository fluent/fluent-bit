#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
set -e

PLATFORM=$(uname -s | tr A-Z a-z)

if [ "$1" = "--sgx" ] && [ "$PLATFORM" = "linux" ]; then
    IWASM="../../../product-mini/platforms/${PLATFORM}-sgx/enclave-sample/iwasm"
    WAMRC="../../../wamr-compiler/build/wamrc -sgx"
else
    IWASM="../../../product-mini/platforms/${PLATFORM}/build/iwasm"
    WAMRC="../../../wamr-compiler/build/wamrc"
fi

if [ ! -e "coremark.wasm" ]; then
    echo "coremark.wasm doesn't exist, please run build.sh first"
    exit
fi

echo ""
echo "Compile coremark.wasm to coremark.aot .."
${WAMRC} -o coremark.aot coremark.wasm

echo ""
echo "Compile coremark.wasm to coremark_pgo.aot .."
${WAMRC} --enable-llvm-pgo -o coremark_pgo.aot coremark.wasm

echo ""
echo "Run coremark_pgo.aot to generate the raw profile data .."
${IWASM} --gen-prof-file=coremark.profraw coremark_pgo.aot

echo ""
echo "Merge the raw profile data to coremark.profdata .."
rm -f coremark.profdata && llvm-profdata merge -output=coremark.profdata coremark.profraw

echo ""
echo "Compile coremark.wasm to coremark_opt.aot with the profile data .."
${WAMRC} --use-prof-file=coremark.profdata -o coremark_opt.aot coremark.wasm

echo ""
echo "Run the coremark native"
./coremark.exe

echo ""
echo "Run the original aot file coremark.aot"
${IWASM} coremark.aot

echo ""
echo "Run the PGO optimized aot file coremark_opt.aot"
${IWASM} coremark_opt.aot

# Show the profile data:
# llvm-profdata show --all-functions --detailed-summary --binary-ids --counts \
# --hot-func-list --memop-sizes --show-prof-sym-list coremark.profraw
