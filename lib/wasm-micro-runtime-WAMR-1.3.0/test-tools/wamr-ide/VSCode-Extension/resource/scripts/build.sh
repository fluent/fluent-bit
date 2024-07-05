#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

docker run --rm --name=wasm-toolchain-ctr \
                -it -v "$(pwd)":/mnt \
                --env=PROJ_PATH="$(pwd)" \
                wasm-toolchain:$2  \
                /bin/bash -c "./build_wasm.sh $1"
