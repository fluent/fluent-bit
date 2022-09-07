# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#!/bin/bash
docker build -t wasm-debug-server:1.0 .

# delete intermediate docker image
sudo docker image prune -f