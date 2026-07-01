# Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project(test-shared-heap)

add_definitions(-DRUN_ON_LINUX)

set(WAMR_BUILD_APP_FRAMEWORK 0)
set(WAMR_BUILD_AOT 1)
set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_FAST_INTERP 1)
set(WAMR_BUILD_JIT 0)
if(WAMR_BUILD_TARGET STREQUAL "X86_32")
    set(WAMR_BUILD_MEMORY64 0)
else()
    set(WAMR_BUILD_MEMORY64 1)
endif()
set(WAMR_BUILD_SHARED_HEAP 1)

# Compile wasm modules
add_subdirectory(wasm-apps)

if (WAMR_BUILD_MEMORY64 EQUAL 1)
   add_subdirectory(wasm-apps/memory64)
endif ()

# if only load this CMake other than load it as subdirectory
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
add_executable(shared_heap_test ${unit_test_sources})

target_link_libraries(shared_heap_test ${LLVM_AVAILABLE_LIBS} gtest_main)

gtest_discover_tests(shared_heap_test)
