# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project(linux_perf_sample)

if(NOT CMAKE_HOST_LINUX)
  message(FATAL_ERROR "This sample only works on linux")
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)
find_package(WASISDK REQUIRED)

################  runtime settings  ################
string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
include(CheckPIESupported)

# AOT and JIT byd default
set(WAMR_BUILD_AOT 1)
set(WAMR_BUILD_INTERP 0)
set(WAMR_BUILD_JIT 1)
# wasm32-wasi
set(WAMR_BUILD_LIBC_BUILTIN 0)
set(WAMR_BUILD_LIBC_WASI 1)
# mvp
set(WAMR_BUILD_BULK_MEMORY 1)
set(WAMR_BUILD_REF_TYPES 1)
set(WAMR_BUILD_SIMD 1)
set(WAMR_BUILD_TAIL_CALL 1)
# trap information
set(WAMR_BUILD_DUMP_CALL_STACK 1)
# linux perf
set(WAMR_BUILD_LINUX_PERF 1)
#
#set(WAMR_BUILD_THREAD_MGR 0)

# vmlib
set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib SHARED ${WAMR_RUNTIME_LIB_SOURCE})
target_include_directories(vmlib INTERFACE ${WAMR_ROOT_DIR}/core/iwasm/include)
target_link_libraries (vmlib ${LLVM_AVAILABLE_LIBS} -lm -ldl)

################ host  ################
add_executable(${PROJECT_NAME} host/demo.c)
target_link_libraries(${PROJECT_NAME} vmlib)

################ aot + wasm  ################
include(ExternalProject)
ExternalProject_Add(wasm
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wasm"
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -S ${CMAKE_CURRENT_SOURCE_DIR}/wasm -B build
                      -DCMAKE_TOOLCHAIN_FILE=${WASISDK_TOOLCHAIN}
  BUILD_COMMAND     ${CMAKE_COMMAND} --build build
  INSTALL_COMMAND   ${CMAKE_COMMAND} --install build --prefix ${CMAKE_CURRENT_BINARY_DIR}
)