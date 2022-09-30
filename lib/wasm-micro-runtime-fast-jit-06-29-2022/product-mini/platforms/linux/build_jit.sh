#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

rm -fr build && mkdir build
cd build
# By default LazyJIT is enabled, to disable it:
# cmake .. -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=0
cmake .. -DWAMR_BUILD_JIT=1
make -j ${nproc}
cd ..
