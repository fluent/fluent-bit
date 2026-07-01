# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project (test-linear-memory-aot)

add_definitions (-DRUN_ON_LINUX)

set (WAMR_BUILD_LIBC_WASI 0)
set (WAMR_BUILD_APP_FRAMEWORK 0)
set (WAMR_BUILD_MEMORY_PROFILING 1)
set (WAMR_BUILD_INTERP 0)
set (WAMR_BUILD_AOT 1)

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

# Test case: .aot file with hardware bound check.
add_executable (linear_memory_test_aot ${unit_test_sources})
target_link_libraries (linear_memory_test_aot gtest_main)
gtest_discover_tests(linear_memory_test_aot)
target_compile_definitions(linear_memory_test_aot PRIVATE WAMR_DISABLE_HW_BOUND_CHECK=0)

# Ensure that aot compiled is completed before linear_memory_test_aot is built
set(dummy_output "${CMAKE_CURRENT_BINARY_DIR}/dummy_output")

add_custom_command(OUTPUT ${dummy_output}
  COMMAND ./build_aot.sh
  COMMAND ${CMAKE_COMMAND} -E touch ${dummy_output}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/build_aot.sh
  COMMENT "Executing script to compile aot files"
  VERBATIM
)

add_custom_target(
  RunBuildAot ALL
  DEPENDS ${dummy_output}
)

add_dependencies(linear_memory_test_aot RunBuildAot)

add_custom_command(TARGET linear_memory_test_aot POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  ${CMAKE_CURRENT_SOURCE_DIR}/build/*.aot
  ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Copy aot files to the directory: build/linear-memory-aot."
)

# Test case: .aot file with no hardware bound check.
add_executable (linear_memory_test_aot_no_hw_bound ${unit_test_sources})
target_link_libraries (linear_memory_test_aot_no_hw_bound gtest_main)
gtest_discover_tests(linear_memory_test_aot_no_hw_bound)
target_compile_definitions(linear_memory_test_aot_no_hw_bound PRIVATE WAMR_DISABLE_HW_BOUND_CHECK=1)
