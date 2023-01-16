# Copyright (C) 2022 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.0)
project(file)

################ wasm application ###############
add_subdirectory(src)
add_subdirectory(wasm-app)
