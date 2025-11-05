#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set -e

docker run --rm -it --name=wasm-debug-server-ctr \
           -v "$(pwd)":/mnt \
           -p 1234:1234 \
           wasm-debug-server:$2 \
           /bin/bash -c "./debug.sh $1 $3"
