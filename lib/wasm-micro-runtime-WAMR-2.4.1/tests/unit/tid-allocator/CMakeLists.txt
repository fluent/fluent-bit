# Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project (tid_allocator_tests)

if (NOT DEFINED WAMR_BUILD_LIB_WASI_THREADS)
  set (WAMR_BUILD_LIB_WASI_THREADS 1)
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_PLATFORM)
  string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
endif ()

include (../unit_common.cmake)

add_library (tid_allocator_vmlib ${WAMR_RUNTIME_LIB_SOURCE})
add_library (wamr_gtest_main main.cpp)
target_link_libraries (wamr_gtest_main PUBLIC gtest tid_allocator_vmlib)

function (create_wamr_unit_test test_name)
    set (sources ${ARGN})
    add_executable (${test_name} ${sources})
    target_link_libraries (
        ${test_name}
        wamr_gtest_main
        tid_allocator_vmlib
        ${LLVM_AVAILABLE_LIBS}
    )
    gtest_discover_tests (${test_name})
    endfunction ()

include (${IWASM_DIR}/libraries/lib-wasi-threads/unit-test/lib_wasi_threads_unit_tests.cmake)

