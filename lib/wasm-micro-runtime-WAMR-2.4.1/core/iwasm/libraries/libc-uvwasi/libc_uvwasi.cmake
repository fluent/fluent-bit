# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Yes. To solve the compatibility issue with CMAKE (>= 4.0), we need to update
# our `cmake_minimum_required()` to 3.5. However, there are CMakeLists.txt
# from 3rd parties that we should not alter. Therefore, in addition to
# changing the `cmake_minimum_required()`, we should also add a configuration
# here that is compatible with earlier versions.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 FORCE)

set (LIBC_WASI_DIR ${CMAKE_CURRENT_LIST_DIR})

set (LIBUV_VERSION v1.51.0)

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
    FetchContent_MakeAvailable(libuv)
    include_directories("${libuv_SOURCE_DIR}/include")
    set (LIBUV_LIBRARIES uv_a)
    set_target_properties(uv_a PROPERTIES POSITION_INDEPENDENT_CODE 1)
endif()

## uvwasi
find_package(UVWASI QUIET)
if (UVWASI_FOUND)
    include_directories(${UVWASI_INCLUDE_DIR})
else()
    FetchContent_Declare(
        uvwasi
        GIT_REPOSITORY https://github.com/nodejs/uvwasi.git
        GIT_TAG 392e1f1c1c8a2d2102c9f2e0b9f35959a149d133
    )
    FetchContent_MakeAvailable(uvwasi)
    include_directories("${uvwasi_SOURCE_DIR}/include")
    set (UVWASI_LIBRARIES uvwasi_a)
    set_target_properties(uvwasi_a PROPERTIES POSITION_INDEPENDENT_CODE 1)
endif()

set (UV_A_LIBS ${LIBUV_LIBRARIES} ${UVWASI_LIBRARIES})

file (GLOB_RECURSE source_all ${LIBC_WASI_DIR}/*.c)

set (LIBC_WASI_SOURCE ${source_all})
