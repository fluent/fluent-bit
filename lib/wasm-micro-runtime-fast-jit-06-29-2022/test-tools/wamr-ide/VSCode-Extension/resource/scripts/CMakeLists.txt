# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.9)

project(Main)

include(${CMAKE_CURRENT_SOURCE_DIR}/project.cmake)

set (CMAKE_SYSROOT /opt/wamr-sdk/app/libc-builtin-sysroot)

set (CMAKE_C_FLAGS " -nostdlib -g -Wno-unused-command-line-argument " CACHE INTERNAL "")

set (CMAKE_CXX_FLAGS " -nostdlib -g" CACHE INTERNAL "")

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -z stack-size=${STACK_SIZE}")

set (CMAKE_EXE_LINKER_FLAGS
    "-Wl,--initial-memory=${INIT_MEM_SIZE},--max-memory=${MAX_MEM_SIZE}, \
     -Wl,--no-entry,")

set (CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} \
     ${EXPORTED_SYMBOLS},")

set (CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} \
    -Wl,--allow-undefined-file=${CMAKE_SYSROOT}/share/defined-symbols.txt" CACHE INTERNAL "")

set (SRC_LIST
    ${PROJECT_SRC_LIST})

set (HEADER_LIST
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${PROJECT_INCLUDES})

include_directories(${HEADER_LIST})

add_executable (${OUTPUT_FILE_NAME} ${SRC_LIST})

