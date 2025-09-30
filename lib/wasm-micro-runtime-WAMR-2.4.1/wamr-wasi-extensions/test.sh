#! /bin/sh

# Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

PREFIX=${1:-/tmp/wamr}

./build_libs.sh ${PREFIX}
./build_samples.sh ${PREFIX}
