# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#!/bin/bash
set -x

# create mount directory on host
if [ ! -d host_mnt ];then
    mkdir host_mnt
fi

sudo docker run --name=wasm-toolchain-provider-ctr \
                -it -v $(pwd)/host_mnt:/mnt \
                wasm-toolchain-provider:1.0 \
                /bin/bash
