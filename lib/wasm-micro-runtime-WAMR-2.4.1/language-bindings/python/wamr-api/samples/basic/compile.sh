#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

/opt/wasi-sdk/bin/clang     \
    -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
    -Wl,--strip-all,--no-entry -nostdlib \
    -Wl,--export=sum\
    -Wl,--allow-undefined \
    -o sum.wasm sum.c
