# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_COMMON_POSIX_DIR ${CMAKE_CURRENT_LIST_DIR})

file (GLOB_RECURSE source_all ${PLATFORM_COMMON_POSIX_DIR}/*.c)

if (NOT WAMR_BUILD_LIBC_WASI EQUAL 1)
    list(REMOVE_ITEM source_all
        ${PLATFORM_COMMON_POSIX_DIR}/posix_file.c
        ${PLATFORM_COMMON_POSIX_DIR}/posix_clock.c
    )
endif()

if ((NOT WAMR_BUILD_LIBC_WASI EQUAL 1) AND (NOT WAMR_BUILD_DEBUG_INTERP EQUAL 1))
    list(REMOVE_ITEM source_all
        ${PLATFORM_COMMON_POSIX_DIR}/posix_socket.c
    )
else()
    include (${CMAKE_CURRENT_LIST_DIR}/../libc-util/platform_common_libc_util.cmake)
    set(source_all ${source_all} ${PLATFORM_COMMON_LIBC_UTIL_SOURCE})
endif()

# This is to support old CMake version. Newer version of CMake could use
# list APPEND/POP_BACK methods.
include(CheckSymbolExists)
set (CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE ${CMAKE_REQUIRED_DEFINITIONS})
check_symbol_exists (mremap "sys/mman.h" MREMAP_EXISTS)
list (REMOVE_AT CMAKE_REQUIRED_DEFINITIONS 0)

if(MREMAP_EXISTS)
    add_definitions (-DWASM_HAVE_MREMAP=1)
    add_definitions (-D_GNU_SOURCE)
else()
    add_definitions (-DWASM_HAVE_MREMAP=0)
    include (${CMAKE_CURRENT_LIST_DIR}/../memory/platform_api_memory.cmake)
    set (source_all ${source_all} ${PLATFORM_COMMON_MEMORY_SOURCE})
endif()

set (PLATFORM_COMMON_POSIX_SOURCE ${source_all} )
