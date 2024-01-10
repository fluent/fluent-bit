# Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project (wamr_unit_tests)

include (CTest)

if (NOT DEFINED WAMR_BUILD_INTERP)
  # Enable Interpreter by default
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_PLATFORM)
  string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
endif ()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library (vmlib ${WAMR_RUNTIME_LIB_SOURCE})

include (FetchContent)
FetchContent_Declare (
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set (gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable (googletest)

include (GoogleTest)

add_library (wamr_gtest_main main.cpp)
target_link_libraries (wamr_gtest_main PUBLIC gtest vmlib)

function (create_wamr_unit_test test_name)
    set (sources ${ARGN})
    add_executable (${test_name} ${sources})
    target_link_libraries (
        ${test_name}
        wamr_gtest_main
        vmlib
        ${LLVM_AVAILABLE_LIBS}
    )
    gtest_discover_tests (${test_name})
    endfunction ()

if (WAMR_BUILD_LIB_WASI_THREADS EQUAL 1)
    include (${IWASM_DIR}/libraries/lib-wasi-threads/unit-test/lib_wasi_threads_unit_tests.cmake)
endif ()
