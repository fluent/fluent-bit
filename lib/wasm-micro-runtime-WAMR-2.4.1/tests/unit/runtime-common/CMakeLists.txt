# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project(test-runtime-common)

add_definitions(-DRUN_ON_LINUX)

set(WAMR_BUILD_LIBC_WASI 0)
set(WAMR_BUILD_APP_FRAMEWORK 0)

include(../unit_common.cmake)

set(LLVM_SRC_ROOT "${WAMR_ROOT_DIR}/core/deps/llvm")

if(NOT EXISTS "${LLVM_SRC_ROOT}/build")
  message(FATAL_ERROR "Cannot find LLVM dir: ${LLVM_SRC_ROOT}/build")
endif()

set(CMAKE_PREFIX_PATH "${LLVM_SRC_ROOT}/build;${CMAKE_PREFIX_PATH}")
find_package(LLVM REQUIRED CONFIG)
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB_RECURSE source_all ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)

set(UNIT_SOURCE ${source_all})

aux_source_directory(. SRC_LIST)

set(unit_test_sources
  ${UNIT_SOURCE}
  ${WAMR_RUNTIME_LIB_SOURCE}
  ${UNCOMMON_SHARED_SOURCE}
  ${SRC_LIST}
)

add_executable(runtime_common_test ${unit_test_sources})

target_link_libraries(runtime_common_test ${LLVM_AVAILABLE_LIBS} gtest_main)

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
  BuildAot ALL
  DEPENDS ${dummy_output}
)

add_dependencies(runtime_common_test BuildAot)

add_custom_command(TARGET runtime_common_test POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
  ${CMAKE_CURRENT_LIST_DIR}/wasm-apps/main.wasm ${CMAKE_CURRENT_LIST_DIR}/wasm-apps/main.aot
  ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Copy main.wasm and main.aot to the directory: build/runtime-common."
)

gtest_discover_tests(runtime_common_test)
