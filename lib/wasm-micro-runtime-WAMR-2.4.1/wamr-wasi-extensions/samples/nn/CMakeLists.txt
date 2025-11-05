# Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED YES)
set(CMAKE_C_EXTENSIONS NO)

project(nn-classification-openvino LANGUAGES C)
add_executable(nn-classification-openvino "app.c")
find_package(wamr-wasi-nn REQUIRED)
target_link_libraries(nn-classification-openvino wamr-wasi-nn)
