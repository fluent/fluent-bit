# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#!/bin/bash
TARGET=$1
./iwasm -g=0.0.0.0:1234 /mnt/build/${TARGET}.wasm