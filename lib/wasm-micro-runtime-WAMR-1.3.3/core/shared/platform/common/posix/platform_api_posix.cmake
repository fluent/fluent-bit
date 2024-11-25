# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_COMMON_POSIX_DIR ${CMAKE_CURRENT_LIST_DIR})

file (GLOB_RECURSE source_all ${PLATFORM_COMMON_POSIX_DIR}/*.c)

if (NOT WAMR_BUILD_LIBC_WASI EQUAL 1)
    list(REMOVE_ITEM source_all
        ${PLATFORM_COMMON_POSIX_DIR}/posix_file.c
        ${PLATFORM_COMMON_POSIX_DIR}/posix_clock.c
        ${PLATFORM_COMMON_POSIX_DIR}/posix_socket.c
    )
else()
    include (${CMAKE_CURRENT_LIST_DIR}/../libc-util/platform_common_libc_util.cmake)
    set(source_all ${source_all} ${PLATFORM_COMMON_LIBC_UTIL_SOURCE})
endif()

set (PLATFORM_COMMON_POSIX_SOURCE ${source_all} )
