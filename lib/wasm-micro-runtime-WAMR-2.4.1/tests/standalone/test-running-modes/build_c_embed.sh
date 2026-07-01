#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

set -e

cd c-embed
rm -fr build && mkdir build
cmake $1 -B build
cmake --build build -j >/dev/null 2>&1
