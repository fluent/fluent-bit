# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (LIBC_WASI_DIR ${CMAKE_CURRENT_LIST_DIR})

set (LIBUV_VERSION v1.46.0)

add_definitions (-DWASM_ENABLE_LIBC_WASI=1 -DWASM_ENABLE_UVWASI=1)

include(FetchContent)

# Point CMake at the custom modules to find libuv and uvwasi
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")

## libuv
find_package(LIBUV QUIET)
if (LIBUV_FOUND)
    include_directories(${LIBUV_INCLUDE_DIR})
else()
    FetchContent_Declare(
        libuv
        GIT_REPOSITORY https://github.com/libuv/libuv.git
        GIT_TAG ${LIBUV_VERSION}
    )
    FetchContent_GetProperties(libuv)
    if (NOT libuv_POPULATED)
        message("-- Fetching libuv ..")
        FetchContent_Populate(libuv)
        include_directories("${libuv_SOURCE_DIR}/include")
        add_subdirectory(${libuv_SOURCE_DIR} ${libuv_BINARY_DIR} EXCLUDE_FROM_ALL)
        set (LIBUV_LIBRARIES uv_a)
        set_target_properties(uv_a PROPERTIES POSITION_INDEPENDENT_CODE 1)
    endif()
endif()

## uvwasi
find_package(UVWASI QUIET)
if (UVWASI_FOUND)
    include_directories(${UVWASI_INCLUDE_DIR})
else()
    FetchContent_Declare(
        uvwasi
        GIT_REPOSITORY https://github.com/nodejs/uvwasi.git
        GIT_TAG main
    )
    FetchContent_GetProperties(uvwasi)
    if (NOT uvwasi_POPULATED)
        message("-- Fetching uvwasi ..")
        FetchContent_Populate(uvwasi)
        include_directories("${uvwasi_SOURCE_DIR}/include")
        add_subdirectory(${uvwasi_SOURCE_DIR} ${uvwasi_BINARY_DIR} EXCLUDE_FROM_ALL)
        set (UVWASI_LIBRARIES uvwasi_a)
        set_target_properties(uvwasi_a PROPERTIES POSITION_INDEPENDENT_CODE 1)
    endif()
endif()

set (UV_A_LIBS ${LIBUV_LIBRARIES} ${UVWASI_LIBRARIES})

file (GLOB_RECURSE source_all ${LIBC_WASI_DIR}/*.c)

set (LIBC_WASI_SOURCE ${source_all})
