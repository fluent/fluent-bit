#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

set -e

PLATFORM=$(uname -s | tr A-Z a-z)

readonly WAMR_DIR="$PWD/../../.."
rm -fr build && mkdir build && cd build
cmake ${WAMR_DIR}/product-mini/platforms/${PLATFORM} $1
make -j > /dev/null 2>&1
cd ..
