# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# Copyright (C) 2020 TU Bergakademie Freiberg Karl Fessel
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.8.2)

set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")

project(NONE)

enable_language (ASM)

set (WAMR_BUILD_PLATFORM "riot")

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
  # Disable AOT by default.
  set (WAMR_BUILD_AOT 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Disable libc wasi support by default
  set (WAMR_BUILD_LIBC_WASI 0)
endif ()

if (NOT DEFINED WAMR_ROOT_DIR)
  # this assumption is true if this file is copied to WAMR_ROOT
  set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
endif ()

# Override the global heap size for small devices
if (NOT DEFINED  WAMR_BUILD_GLOBAL_HEAP_SIZE)
  add_definitions (-DWASM_GLOBAL_HEAP_SIZE=262144) # 256 kB
endif ()


include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

# need includes from RIOT prepare them as a cmake list
string(REGEX MATCHALL "([^\ ]+\ |[^\ ]+$)" RIOT_INCLUDES_LIST "${RIOT_INCLUDES}")

include_directories(SYSTEM ${RIOT_INCLUDES_LIST})

# target_sources( ${WAMR_RUNTIME_LIB_SOURCE} )
# executable linking is done by RIOT build system

add_library( wamr ${WAMR_RUNTIME_LIB_SOURCE})
