# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(wamr_user_mode LANGUAGES C)

# Add the wamr-lib directory
add_subdirectory(lib-wamr-zephyr)

# Link the wamr library to the app target
target_link_libraries(app PRIVATE wamr_lib)

target_sources(app PRIVATE src/main.c)
