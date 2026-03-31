#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

/opt/wasi-sdk/bin/clang     \
    -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
    -Wl,--export=main -Wl,--export=__main_argc_argv \
    -Wl,--export=__data_end -Wl,--export=__heap_base \
    -Wl,--strip-all,--no-entry \
    -Wl,--allow-undefined \
    -Wl,--export=c_func\
    -Wl,--export=add\
    -o func.wasm func.c
