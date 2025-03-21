# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.9)

project (vgl_wasm_runtime)

set (WAMR_BUILD_PLATFORM "linux")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

################  wamr runtime settings  ################

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)

## use library and headers in the SDK
link_directories(${WAMR_ROOT_DIR}/wamr-sdk/out/littlevgl/runtime-sdk/lib)
include_directories(
    ${WAMR_ROOT_DIR}/wamr-sdk/out/littlevgl/runtime-sdk/include
    ${WAMR_ROOT_DIR}/wamr-sdk/out/littlevgl/runtime-sdk/include/bi-inc/deps
    ${WAMR_ROOT_DIR}/core/shared/utils
    ${WAMR_ROOT_DIR}/core/shared/platform/${WAMR_BUILD_PLATFORM}
)

###############  application related  ###############
include_directories(${CMAKE_CURRENT_LIST_DIR}/src)

add_executable (vgl_wasm_runtime src/platform/${WAMR_BUILD_PLATFORM}/main.c
                src/platform/${WAMR_BUILD_PLATFORM}/iwasm_main.c
                src/platform/${WAMR_BUILD_PLATFORM}/display_indev.c
                src/platform/${WAMR_BUILD_PLATFORM}/mouse.c)

target_link_libraries (vgl_wasm_runtime vmlib -lm -ldl -lpthread -lSDL2)

