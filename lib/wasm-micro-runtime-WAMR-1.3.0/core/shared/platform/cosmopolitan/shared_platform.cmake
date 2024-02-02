# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# Copyright (C) 2023 Dylibso.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_COSMOPOLITAN)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

include (${CMAKE_CURRENT_LIST_DIR}/../common/posix/platform_api_posix.cmake)

file (GLOB_RECURSE source_all ${PLATFORM_SHARED_DIR}/*.c)

set (PLATFORM_SHARED_SOURCE ${source_all} ${PLATFORM_COMMON_POSIX_SOURCE})

file (GLOB header ${PLATFORM_SHARED_DIR}/../include/*.h)
LIST (APPEND RUNTIME_LIB_HEADER_LIST ${header})
