# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#!/bin/bash
sudo docker pull gcc:9.3.0
sudo docker pull ubuntu:20.04
sudo docker build -t  wasm-toolchain-provider:1.0 .

# delete intermediate docker image
sudo docker image prune -f
