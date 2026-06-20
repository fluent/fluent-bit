#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

docker run --rm -it --name=wasm-debug-server-ctr \
           -v "$(pwd)":/mnt \
           wasm-debug-server:$2 \
           /bin/bash -c "./run.sh $1 $3"
