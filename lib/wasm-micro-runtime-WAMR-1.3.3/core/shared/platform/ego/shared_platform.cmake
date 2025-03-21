# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_EGO)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

include (${CMAKE_CURRENT_LIST_DIR}/../common/posix/platform_api_posix.cmake)

set (PLATFORM_SHARED_SOURCE
  ${PLATFORM_COMMON_POSIX_SOURCE}
  ${CMAKE_CURRENT_LIST_DIR}/platform_init.c
)

LIST (APPEND RUNTIME_LIB_HEADER_LIST
  ${CMAKE_CURRENT_LIST_DIR}/platform_internal.h
)