#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

rm -rf build
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../../../../wamr-sdk/app/wamr_toolchain.cmake
make