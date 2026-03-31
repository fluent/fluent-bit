# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(wasm-apps-wasm64)

set(WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../..)
set(WAMRC_ROOT_DIR ${WAMR_ROOT_DIR}/wamr-compiler/build)

set(CMAKE_SYSTEM_PROCESSOR wasm64)
set(CMAKE_SYSROOT ${WAMR_ROOT_DIR}/wamr-sdk/app/libc-builtin-sysroot)

if (NOT DEFINED WASI_SDK_DIR)
    set(WASI_SDK_DIR "/opt/wasi-sdk")
endif ()

set(CMAKE_C_FLAGS "-nostdlib -pthread -Qunused-arguments")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -z stack-size=8192 -nostdlib -O0 --target=wasm64")
set(CMAKE_C_COMPILER_TARGET "wasm64")
set(CMAKE_C_COMPILER "${WASI_SDK_DIR}/bin/clang")

set(DEFINED_SYMBOLS
        "${WAMR_ROOT_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt")

set(CMAKE_EXE_LINKER_FLAGS
        "-Wl,--no-entry           \
      -Wl,--initial-memory=65536  \
      -Wl,--export-all            \
      -Wl,--allow-undefined"
        )

set (WAMR_COMPILER_FLAGS --opt-level=3 --bounds-checks=1 --enable-shared-heap)
set (WAMR_COMPILER_CHAIN_FLAGS --opt-level=3 --bounds-checks=1 --enable-shared-chain)

function(copy_wasm TARGET_NAME)
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}
                ${CMAKE_CURRENT_BINARY_DIR}/../../
        COMMENT "Copy ${TARGET_NAME} to the same directory of google test"
    )
endfunction()

function(compile_and_copy_aot_from TARGET_NAME)
    string(REPLACE ".wasm" ".aot" AOT_TARGET ${TARGET_NAME})
    string(REPLACE ".wasm" "_chain.aot" AOT_CHAIN_TARGET ${TARGET_NAME})

    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${WAMRC_ROOT_DIR}/wamrc ${WAMR_COMPILER_FLAGS}
                -o ${AOT_TARGET}
                ${TARGET_NAME}
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_BINARY_DIR}/${AOT_TARGET}
                ${CMAKE_CURRENT_BINARY_DIR}/../../
        COMMAND ${WAMRC_ROOT_DIR}/wamrc ${WAMR_COMPILER_CHAIN_FLAGS}
                -o ${AOT_CHAIN_TARGET}
                ${TARGET_NAME}
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_BINARY_DIR}/${AOT_CHAIN_TARGET}
                ${CMAKE_CURRENT_BINARY_DIR}/../../
        COMMENT "Compile and copy ${AOT_TARGET} ${AOT_CHAIN_TARGET} to the same directory of google test"
    )
endfunction()

add_executable(test64.wasm ../test.c)
target_link_libraries(test64.wasm)
copy_wasm(test64.wasm)
compile_and_copy_aot_from(test64.wasm)
