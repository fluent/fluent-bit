#!/bin/sh

# Copyright (C) 2022 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

rm -rf ./iwasm-proj
git clone https://github.com/leetal/ios-cmake.git ios-cmake
cmake -Biwasm-proj -G Xcode -DDEPLOYMENT_TARGET=11.0 -DPLATFORM=OS64 -DENABLE_BITCODE=0 -DCMAKE_TOOLCHAIN_FILE=ios-cmake/ios.toolchain.cmake .
