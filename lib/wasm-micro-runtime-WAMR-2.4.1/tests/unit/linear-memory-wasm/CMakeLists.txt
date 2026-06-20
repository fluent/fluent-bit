# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project (test-linear-memory-wasm)

add_definitions (-DRUN_ON_LINUX)

set (WAMR_BUILD_LIBC_WASI 0)
set (WAMR_BUILD_APP_FRAMEWORK 0)
set (WAMR_BUILD_MEMORY_PROFILING 1)
set (WAMR_BUILD_INTERP 1)
set (WAMR_BUILD_AOT 0)

include (../unit_common.cmake)

include_directories (${CMAKE_CURRENT_SOURCE_DIR})

file (GLOB_RECURSE source_all ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)

set (UNIT_SOURCE ${source_all})

set (unit_test_sources
    ${UNIT_SOURCE}
    ${WAMR_RUNTIME_LIB_SOURCE}
    ${UNCOMMON_SHARED_SOURCE}
    ${SRC_LIST}
    ${PLATFORM_SHARED_SOURCE}
    ${UTILS_SHARED_SOURCE}
    ${MEM_ALLOC_SHARED_SOURCE}
    ${LIB_HOST_AGENT_SOURCE}
    ${NATIVE_INTERFACE_SOURCE}
    ${LIBC_BUILTIN_SOURCE}
    ${IWASM_COMMON_SOURCE}
    ${IWASM_INTERP_SOURCE}
    ${IWASM_AOT_SOURCE}
    ${IWASM_COMPL_SOURCE}
    ${WASM_APP_LIB_SOURCE_ALL}
)

# Test case: .wasm file with hardware bound check.
add_executable (linear_memory_test_wasm ${unit_test_sources})
target_link_libraries (linear_memory_test_wasm gtest_main)
gtest_discover_tests(linear_memory_test_wasm)
target_compile_definitions(linear_memory_test_wasm PRIVATE WAMR_DISABLE_HW_BOUND_CHECK=0)

add_custom_command(TARGET linear_memory_test_wasm POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  ${CMAKE_CURRENT_LIST_DIR}/wasm_files/*
  ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Copy wasm files to the directory: build/linear-memory-wasm."
)

# Test case: .wasm file with no hardware bound check.
add_executable (linear_memory_test_wasm_no_hw_bound ${unit_test_sources})
target_link_libraries (linear_memory_test_wasm_no_hw_bound gtest_main)
gtest_discover_tests(linear_memory_test_wasm_no_hw_bound)
target_compile_definitions(linear_memory_test_wasm_no_hw_bound PRIVATE WAMR_DISABLE_HW_BOUND_CHECK=1)
