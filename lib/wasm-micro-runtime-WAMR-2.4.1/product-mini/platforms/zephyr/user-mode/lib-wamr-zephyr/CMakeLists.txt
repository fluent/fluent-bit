# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

set (WAMR_BUILD_PLATFORM "zephyr")

# Build as X86_32 by default, change to "AARCH64[sub]", "ARM[sub]", "THUMB[sub]", "MIPS" or "XTENSA"
# if we want to support arm, thumb, mips or xtensa
if (NOT DEFINED WAMR_BUILD_TARGET)
  set (WAMR_BUILD_TARGET "X86_32")
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
  # Enable Interpreter by default
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_AOT)
  # Enable AOT by default.
  set (WAMR_BUILD_AOT 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Disable libc wasi support by default, in the future, 
  # it can be enabled if libc wasi file/socket/lock support is ready on Zephyr platform
  set (WAMR_BUILD_LIBC_WASI 0)
endif ()

if (WAMR_BUILD_TARGET STREQUAL "RISCV64_LP64" OR WAMR_BUILD_TARGET STREQUAL "RISCV32_ILP32")
  set (WAMR_BUILD_FAST_INTERP 1)
endif ()

# Limited to global heap usage in Zephyr user mode
set (WAMR_BUILD_GLOBAL_HEAP_POOL 1)

# Override the global heap size for small devices
if (NOT DEFINED WAMR_BUILD_GLOBAL_HEAP_SIZE)
  set (WAMR_BUILD_GLOBAL_HEAP_SIZE 40960) # 40 KB
endif ()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

# Embed WAMR as a Zephyr library
zephyr_library_named (wamr_lib)

# Add source files to the library
zephyr_library_sources (
  ${WAMR_RUNTIME_LIB_SOURCE} 
  wamr_lib.c
)

# Specify the memory partition where all globals(including the WAMR global heap buffer)
# in the library should be placed. This partition will be defined in the app source code
# and added to the use-mode thread that uses the WAMR library.
zephyr_library_app_memory (wamr_partition)
