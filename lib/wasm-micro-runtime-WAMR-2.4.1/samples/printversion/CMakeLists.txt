# Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.16)

project(printversion LANGUAGES C)

add_executable(printversion printversion.c)
find_package(iwasm REQUIRED)
target_link_libraries(printversion iwasm::vmlib)
