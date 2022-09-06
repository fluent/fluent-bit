# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#!/bin/bash

target_name=$1

docker run -it --name=wasm-debug-server-ctr \
           -v $(pwd):/mnt \
           -p 1234:1234 \
           wasm-debug-server:1.0 \
           /bin/bash -c "./debug.sh ${target_name}"

docker stop wasm-debug-server-ctr && docker rm wasm-debug-server-ctr