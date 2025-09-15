#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

PLATFORM=$(uname -s | tr A-Z a-z)

if [ "$1" = "--sgx" ] && [ "$PLATFORM" = "linux" ]; then
    IWASM="../../../product-mini/platforms/${PLATFORM}-sgx/enclave-sample/iwasm"
    WAMRC="../../../wamr-compiler/build/wamrc -sgx"
else
    IWASM="../../../product-mini/platforms/${PLATFORM}/build/iwasm"
    WAMRC="../../../wamr-compiler/build/wamrc"
fi

if [ ! -e "dhrystone.wasm" ]; then
    echo "dhrystone.wasm doesn't exist, please run build.sh first"
    exit
fi

echo ""
echo "Compile dhrystone.wasm to dhrystone.aot .."
${WAMRC} -o dhrystone.aot dhrystone.wasm

echo ""
echo "Compile dhrystone.wasm to dhrystone_pgo.aot .."
${WAMRC} --enable-llvm-pgo -o dhrystone_pgo.aot dhrystone.wasm

echo ""
echo "Run dhrystone_pgo.aot to generate the raw profile data .."
${IWASM} --gen-prof-file=dhrystone.profraw dhrystone_pgo.aot

echo ""
echo "Merge the raw profile data to dhrystone.profdata .."
rm -f dhrystone.profdata && llvm-profdata merge -output=dhrystone.profdata dhrystone.profraw

echo ""
echo "Compile dhrystone.wasm to dhrystone_opt.aot with the profile data .."
${WAMRC} --use-prof-file=dhrystone.profdata -o dhrystone_opt.aot dhrystone.wasm

echo ""
echo "Run the dhrystone native"
./dhrystone_native

echo ""
echo "Run the original aot file dhrystone.aot"
${IWASM} dhrystone.aot

echo ""
echo "Run the PGO optimized aot file dhrystone_opt.aot"
${IWASM} dhrystone_opt.aot

# Show the profile data:
# llvm-profdata show --all-functions --detailed-summary --binary-ids --counts \
# --hot-func-list --memop-sizes --show-prof-sym-list dhrystone.profraw
