# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project(wasm-apps-custom-section)

# Add -g option so there will be debugger related custom sections
add_custom_target(app.wasm ALL
    COMMAND /opt/wasi-sdk/bin/clang -g -nostdlib
            -Wl,--no-entry,--export-all
            -o ${CMAKE_CURRENT_BINARY_DIR}/app.wasm
            ${CMAKE_CURRENT_LIST_DIR}/app.c
)
