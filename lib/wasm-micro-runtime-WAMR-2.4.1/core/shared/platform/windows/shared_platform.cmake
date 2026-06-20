# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_WINDOWS)
add_definitions(-DHAVE_STRUCT_TIMESPEC)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
enable_language(CXX)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

file (GLOB_RECURSE source_all ${PLATFORM_SHARED_DIR}/*.c
			      ${PLATFORM_SHARED_DIR}/*.cpp)

if (NOT WAMR_BUILD_LIBC_WASI EQUAL 1)
    list(REMOVE_ITEM source_all ${PLATFORM_SHARED_DIR}/win_file.c)
elseif (WAMR_BUILD_LIBC_UVWASI EQUAL 1)
    # uvwasi doesn't need to compile win_file.c
    list(REMOVE_ITEM source_all ${PLATFORM_SHARED_DIR}/win_file.c)
else()
    include (${CMAKE_CURRENT_LIST_DIR}/../common/libc-util/platform_common_libc_util.cmake)
    set(source_all ${source_all} ${PLATFORM_COMMON_LIBC_UTIL_SOURCE})
endif()

include (${CMAKE_CURRENT_LIST_DIR}/../common/memory/platform_api_memory.cmake)
set (source_all ${source_all} ${PLATFORM_COMMON_MEMORY_SOURCE})

set (PLATFORM_SHARED_SOURCE ${source_all})

file (GLOB header ${PLATFORM_SHARED_DIR}/../include/*.h)
LIST (APPEND RUNTIME_LIB_HEADER_LIST ${header})
