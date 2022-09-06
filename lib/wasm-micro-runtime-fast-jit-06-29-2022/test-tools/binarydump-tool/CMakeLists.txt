# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.8)

project(binarydump)

add_definitions (-Wextra -pedantic -Wno-unused-parameter)

add_executable (binarydump binarydump.c)

