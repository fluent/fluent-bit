# Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project(wamr-wasi-extensions LANGUAGES C)

add_subdirectory(nn)
add_subdirectory(socket)
