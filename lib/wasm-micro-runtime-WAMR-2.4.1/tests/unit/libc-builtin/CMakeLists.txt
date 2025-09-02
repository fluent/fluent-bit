# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project (test-libc-builtin)

add_definitions (-DRUN_ON_LINUX)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

set (WAMR_BUILD_LIBC_WASI 0)
set (WAMR_BUILD_APP_FRAMEWORK 0)

include (../unit_common.cmake)

include_directories (${CMAKE_CURRENT_SOURCE_DIR})

file (GLOB_RECURSE source_all ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)

set (UNIT_SOURCE ${source_all})

set (unit_test_sources
     ${UNIT_SOURCE}
     ${WAMR_RUNTIME_LIB_SOURCE}
    )

add_executable (libc_builtin_test ${unit_test_sources})

target_link_libraries (libc_builtin_test gtest_main)

gtest_discover_tests(libc_builtin_test)
