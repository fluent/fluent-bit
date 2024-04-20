# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.16)
project(wasi-nn C CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../..)
set(WASI_NN_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

#### libvmlib ####
# NOTE: we build vmlib as a shared library here so that it can be
# shared between iwasm and native libraries.
include(${WASI_NN_ROOT_DIR}/cmake/iwasm_helper.cmake)
include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib SHARED ${WAMR_RUNTIME_LIB_SOURCE})

# iwasm
include(${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)
set(RUNTIME_SOURCE_ALL
  ${WAMR_ROOT_DIR}/product-mini/platforms/${WAMR_BUILD_PLATFORM}/main.c
  ${UNCOMMON_SHARED_SOURCE}
)

add_executable(iwasm ${RUNTIME_SOURCE_ALL})
target_link_libraries(iwasm vmlib -lpthread -lm -ldl)

#### TensorFlow ####

include(${WASI_NN_ROOT_DIR}/cmake/wasi_nn.cmake)

#### WASI-NN ####

include_directories(
  ${WAMR_ROOT_DIR}/core/iwasm/include
  ${WAMR_ROOT_DIR}/core/shared/utils
  ${WAMR_ROOT_DIR}/core/shared/platform/linux
)

add_library(wasi-nn SHARED
  ${WASI_NN_SOURCES}
)

# Add `get_native_lib` symbol
target_compile_definitions(wasi-nn PUBLIC
  WASI_NN_SHARED
)

target_link_libraries(wasi-nn
  ${WASI_NN_LIBS}
  vmlib
)
