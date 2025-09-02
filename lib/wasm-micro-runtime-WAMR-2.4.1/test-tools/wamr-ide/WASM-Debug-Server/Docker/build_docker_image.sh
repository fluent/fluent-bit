#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

docker build -t wasm-debug-server:1.0 .

# delete intermediate docker image
docker image prune -f
