# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(wasm-apps)

set(WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../..)

if (APPLE)
    set (HAVE_FLAG_SEARCH_PATHS_FIRST 0)
    set (CMAKE_C_LINK_FLAGS "")
    set (CMAKE_CXX_LINK_FLAGS "")
endif ()
# have to be debug for peterson lock algorithm
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set (CMAKE_SYSROOT                  ${WAMR_ROOT_DIR}/wamr-sdk/app/libc-builtin-sysroot)

if (NOT DEFINED WASI_SDK_DIR)
    set (WASI_SDK_DIR               "/opt/wasi-sdk")
endif ()

set (CMAKE_C_FLAGS                  "-nostdlib -pthread -Qunused-arguments")
set (CMAKE_C_FLAGS                  "${CMAKE_C_FLAGS} -z stack-size=32768")
set (CMAKE_C_COMPILER_TARGET        "wasm32")
set (CMAKE_C_COMPILER               "${WASI_SDK_DIR}/bin/clang")

set (DEFINED_SYMBOLS
"${WAMR_ROOT_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt")

set (CMAKE_EXE_LINKER_FLAGS
     "-Wl,--shared-memory,--max-memory=131072,          \
      -Wl,--no-entry,--strip-all,                       \
      -Wl,--export=__heap_base,--export=__data_end      \
      -Wl,--export=__wasm_call_ctors                    \
      -Wl,--export=main -Wl,--export=__main_argc_argv   \
      -Wl,--allow-undefined"
      #-Wl,--allow-undefined-file=${DEFINED_SYMBOLS}"
)

add_executable(atomic_add_sub.wasm atomic_add_sub.c)
target_link_libraries(atomic_add_sub.wasm)

# use peterson lock to test the atomicity of opcode: fence store xchg 
add_executable(peterson_native.wasm peterson_native.c)
target_link_libraries(peterson_native.wasm)

add_executable(atomic_fence.wasm atomic_fence.c)
target_link_libraries(atomic_fence.wasm)

add_executable(atomic_store.wasm atomic_store.c)
target_link_libraries(atomic_store.wasm)

add_executable(atomic_xchg.wasm atomic_xchg.c)
target_link_libraries(atomic_xchg.wasm)

add_executable(atomic_logical.wasm atomic_logical.c)
target_link_libraries(atomic_logical.wasm)

add_executable(atomic_wait_notify.wasm atomic_wait_notify.c)
target_link_libraries(atomic_wait_notify.wasm)