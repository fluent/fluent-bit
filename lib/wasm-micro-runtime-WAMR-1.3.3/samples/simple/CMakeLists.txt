# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.9)

project (simple)

################  wamr runtime settings  ################
message(STATUS "WAMR_BUILD_SDK_PROFILE=${WAMR_BUILD_SDK_PROFILE}")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

if ("$ENV{COLLECT_CODE_COVERAGE}" STREQUAL "1" OR COLLECT_CODE_COVERAGE EQUAL 1)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
endif ()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

## use library and headers in the SDK
link_directories(${WAMR_ROOT_DIR}/wamr-sdk/out/${WAMR_BUILD_SDK_PROFILE}/runtime-sdk/lib)
include_directories(
    ${WAMR_ROOT_DIR}/wamr-sdk/out/${WAMR_BUILD_SDK_PROFILE}/runtime-sdk/include
    ${WAMR_ROOT_DIR}/core/shared/utils
    ${WAMR_ROOT_DIR}/core/shared/platform/linux
)

################  application related  ################

include_directories(${CMAKE_CURRENT_LIST_DIR}/src)

#Note: uncomment below line to use UART mode
#add_definitions (-DCONNECTION_UART)

add_executable (simple src/main.c src/iwasm_main.c)
target_link_libraries (simple vmlib -lm -ldl -lpthread -lrt)


