# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project(test-memory64)

add_definitions(-DRUN_ON_LINUX)

set(WAMR_BUILD_LIBC_WASI 1)
set(WAMR_BUILD_APP_FRAMEWORK 0)
# TODO: Currently only support classic interpreter mode
set(WAMR_BUILD_AOT 0)
set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_FAST_INTERP 0)
set(WAMR_BUILD_JIT 0)
set(WAMR_BUILD_FAST_JIT 0)
set(WAMR_BUILD_MEMORY64 1)
set(WAMR_BUILD_SHARED_MEMORY 1)

# if only load this CMake other than load it as subdirectory
# include(GoogleTest)
include(../unit_common.cmake)

set(LLVM_SRC_ROOT "${WAMR_ROOT_DIR}/core/deps/llvm")

if (NOT EXISTS "${LLVM_SRC_ROOT}/build")
    message(FATAL_ERROR "Cannot find LLVM dir: ${LLVM_SRC_ROOT}/build")
endif ()

set(CMAKE_PREFIX_PATH "${LLVM_SRC_ROOT}/build;${CMAKE_PREFIX_PATH}")
find_package(LLVM REQUIRED CONFIG)
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include(${IWASM_DIR}/compilation/iwasm_compl.cmake)

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

# Now simply link against gtest or gtest_main as needed. Eg
add_executable(memory64_test ${unit_test_sources})

target_link_libraries(memory64_test ${LLVM_AVAILABLE_LIBS} gtest_main)

add_custom_command(TARGET memory64_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/wasm-apps/*.wasm
        ${CMAKE_CURRENT_BINARY_DIR}/
        COMMENT "Copy test wasm files to the directory of google test"
        )

gtest_discover_tests(memory64_test)
