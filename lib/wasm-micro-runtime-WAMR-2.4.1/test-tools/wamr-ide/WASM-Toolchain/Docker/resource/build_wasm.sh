# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#!/bin/bash
export CC=/opt/wasi-sdk/bin/clang
export CXX=/opt/wasi-sdk/bin/clang++

cd /mnt
if [ -d build ];then
  rm -fr build
fi

mkdir -p build && cd build
echo "========> compile wasm with wasi-sdk"
cmake -DWASI_SDK_DIR=/opt/wasi-sdk -DCMAKE_TOOLCHAIN_FILE=/opt/wamr-sdk/app/wamr_toolchain.cmake ../.wamr && make

if [ $? -eq 0 ]; then
  echo "========> compile wasm to AoT with wamrc"
  # target name will be provided:
  #    - user input the target name in IDE
  #    - generated wasm binary name will be set as user's input target name
  #    - aot binary name should be the same as wasm binary name
  #    - target name will be provided through 1st parameter
  wamrc -o $1.aot $1.wasm
fi