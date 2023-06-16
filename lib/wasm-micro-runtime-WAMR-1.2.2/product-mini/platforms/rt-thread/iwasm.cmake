#
# Copyright (c) 2021, RT-Thread Development Team
#
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

set(CMAKE_ASM_COMPILER_WORKS 1)

set(WAMR_BUILD_PLATFORM "rt-thread")
set(WAMR_BUILD_TARGET "ARM")

#set(WAMR_BUILD_INTERP 1)
#set(WAMR_BUILD_FAST_INTERP 1)
#set(WAMR_BUILD_AOT 0)
#set(WAMR_BUILD_JIT 0)
#set(WAMR_BUILD_LIBC_BUILTIN 1)
#set(WAMR_BUILD_LIBC_WASI 0)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
    # Enable Interpreter by default
    set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_AOT)
    # Enable AOT by default.
    set (WAMR_BUILD_AOT 0)
endif ()

# Disable JIT by default.
set (WAMR_BUILD_JIT 0)

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
    # Enable libc builtin support by default
    set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

set (WAMR_BUILD_LIBC_WASI 0)

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
    # Enable fast interpreter
    set (WAMR_BUILD_FAST_INTERP 1)
endif ()

set (WAMR_BUILD_MULTI_MODULE 0)
set (WAMR_BUILD_LIB_PTHREAD 0)
set (WAMR_BUILD_MINI_LOADER 0)
set (WAMR_BUILD_SIMD 0)


set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)

set(CMAKE_ASM_COMPILER_WORKS 1)

include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

file (GLOB wamr_entry_src
        ${WAMR_ROOT_DIR}/product-mini/platforms/rt-thread/rtt_wamr_entry.c
        )

set(WAMR_SOURCE ${wamr_entry_src} ${WAMR_RUNTIME_LIB_SOURCE})


