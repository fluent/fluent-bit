# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.5)
project(hello_world)

set (CMAKE_C_FLAGS          "${CMAKE_C_FLAGS} -O3 -Wno-unused-command-line-argument")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS},--export=main")

add_library(print print.c)

add_executable(hello_world main.c)
target_link_libraries(hello_world print)