# Copyright (C) 2022 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(file_wasm)

set (CMAKE_BUILD_TYPE Debug)  # Otherwise no debug symbols (addr2line)

add_executable(file main.c)
set_target_properties (file PROPERTIES SUFFIX .wasm)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/file.wasm DESTINATION wasm-app)
