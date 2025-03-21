# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(host)

set(CMAKE_BUILD_TYPE Debug)

#
# host
add_executable(example1 ./example1.c)
target_link_libraries(example1 vmlib)
