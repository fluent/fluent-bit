#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

rm -fr build && mkdir build
cd build
cmake .. -DWAMR_BUILD_JIT=1
nproc=$(sysctl -n hw.ncpu)
make -j ${nproc}
cd ..
