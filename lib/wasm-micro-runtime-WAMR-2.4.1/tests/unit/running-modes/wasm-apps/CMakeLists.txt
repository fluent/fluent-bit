# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(wasm-apps)

set(WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../..)

set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(CMAKE_SYSROOT ${WAMR_ROOT_DIR}/wamr-sdk/app/libc-builtin-sysroot)

if (NOT DEFINED WASI_SDK_DIR)
    set(WASI_SDK_DIR "/opt/wasi-sdk")
endif ()

set(CMAKE_C_FLAGS "-nostdlib -pthread -Qunused-arguments")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -z stack-size=8192 -nostdlib")
set(CMAKE_C_COMPILER_TARGET "wasm32")
set(CMAKE_C_COMPILER "${WASI_SDK_DIR}/bin/clang")

set(DEFINED_SYMBOLS
        "${WAMR_ROOT_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt")

set(CMAKE_EXE_LINKER_FLAGS
        "-Wl,--no-entry           \
      -Wl,--initial-memory=65536  \
      -Wl,--export-all            \
      -Wl,--allow-undefined"
        )

add_executable(mytest.wasm mytest.c)
target_link_libraries(mytest.wasm)

add_executable(hello.wasm hello.c)
target_link_libraries(hello.wasm)

add_custom_command(TARGET hello.wasm POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_BINARY_DIR}/hello.wasm
        ${CMAKE_CURRENT_BINARY_DIR}/../
        COMMENT "Copy hello.wasm to the same directory of google test"
        )

add_custom_command(TARGET mytest.wasm POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_BINARY_DIR}/mytest.wasm
        ${CMAKE_CURRENT_BINARY_DIR}/../
        COMMENT "Copy mytest.wasm to the same directory of google test"
        )
