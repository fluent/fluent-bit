# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 2.8)
project(runtime-sdk)

SET (CMAKE_C_FLAGS          "-O3")
set (CMAKE_BUILD_TYPE       Release)

add_definitions(-DBH_MALLOC=wasm_runtime_malloc)
add_definitions(-DBH_FREE=wasm_runtime_free)

if (NOT DEFINED WAMR_BUILD_SDK_PROFILE)
    set (WAMR_BUILD_SDK_PROFILE       "default")
endif ()

if (NOT DEFINED CONFIG_PATH)
    set (CONFIG_PATH       ${CMAKE_CURRENT_LIST_DIR}/../wamr_config_default.cmake)
endif ()

if (NOT EXISTS "${CONFIG_PATH}")
    message (FATAL_ERROR "${CONFIG_PATH} not exist")
endif ()

include(${CONFIG_PATH})

if (NOT DEFINED OUT_DIR)
    set (OUT_DIR      "${CMAKE_CURRENT_LIST_DIR}/../out/${WAMR_BUILD_SDK_PROFILE}")
endif ()
set (RUNTIME_SDK_DIR        "${OUT_DIR}/runtime-sdk")

include(${CMAKE_CURRENT_LIST_DIR}/../../build-scripts/runtime_lib.cmake)

# build vmlib
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

# copy vmlib.a to ${SDK_ROOT}/out/runtime-sdk/lib
add_custom_command(
    TARGET vmlib POST_BUILD

    COMMAND ${CMAKE_COMMAND} -E make_directory ${RUNTIME_SDK_DIR}/lib
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/*.a ${RUNTIME_SDK_DIR}/lib
)

# copy headers to ${SDK_ROOT}/out/runtime-sdk/include
FOREACH (header IN LISTS RUNTIME_LIB_HEADER_LIST)
    execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${RUNTIME_SDK_DIR}/include)
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy "${header}" ${RUNTIME_SDK_DIR}/include)
ENDFOREACH (header)


if (DEFINED EXTRA_SDK_INCLUDE_PATH)
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy_directory ${EXTRA_SDK_INCLUDE_PATH} ${RUNTIME_SDK_DIR}/include)
endif ()

# config.h is not needed when building a runtime product with pre-built library
# erase the file to avoid compile error
file (WRITE ${RUNTIME_SDK_DIR}/include/config.h "")
