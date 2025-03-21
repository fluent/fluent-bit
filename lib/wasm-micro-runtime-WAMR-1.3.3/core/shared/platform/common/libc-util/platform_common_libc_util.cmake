# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 
set (PLATFORM_COMMON_LIBC_UTIL_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${PLATFORM_COMMON_LIBC_UTIL_DIR})

file (GLOB_RECURSE PLATFORM_COMMON_LIBC_UTIL_SOURCE ${PLATFORM_COMMON_LIBC_UTIL_DIR}/*.c)