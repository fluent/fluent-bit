# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# Copyright (C) 2020 TU Bergakademie Freiberg Karl Fessel
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_RIOT)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

# include (${CMAKE_CURRENT_LIST_DIR}/../common/math/platform_api_math.cmake)

file (GLOB_RECURSE source_all ${PLATFORM_SHARED_DIR}/*.c)

set (PLATFORM_SHARED_SOURCE ${source_all} ${PLATFORM_COMMON_MATH_SOURCE})

