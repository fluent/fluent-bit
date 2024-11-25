# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.4.1)

set (CMAKE_VERBOSE_MAKEFILE on)
set (CMAKE_BUILD_TYPE       Release)

# https://github.com/actions/virtual-environments/blob/main/images/linux/Ubuntu2004-Readme.md#environment-variables-3
set (CMAKE_TOOLCHAIN_FILE "$ENV{ANDROID_NDK_LATEST_HOME}/build/cmake/android.toolchain.cmake")
set (ANDROID_SDK $ENV{ANDROID_HOME})
set (ANDROID_NDK $ENV{ANDROID_NDK_LATEST_HOME})

set (ANDROID_ABI "x86")
set (ANDROID_LD lld)
if (NOT DEFINED ANDROID_PLATFORM)
  set (ANDROID_PLATFORM 24)
endif ()

project (iwasm)

set (WAMR_BUILD_PLATFORM      "android")
set (WAMR_BUILD_TARGET        "X86_32")
set (WAMR_BUILD_TYPE          Release)
set (WAMR_BUILD_INTERP        1)
set (WAMR_BUILD_AOT           1)
set (WAMR_BUILD_JIT           0)
set (WAMR_BUILD_LIBC_BUILTIN  1)
set (WAMR_BUILD_LIBC_WASI     1)

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR_BUILD_TARGET, currently values supported:
# "X86_64", "AMD_64", "X86_32", "AARCH64[sub]", "ARM[sub]", "THUMB[sub]", "MIPS", "XTENSA"
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
    # Build as X86_32 by default in 32-bit platform
    set (WAMR_BUILD_TARGET "X86_32")
  else ()
    message(SEND_ERROR "Unsupported build target platform!")
  endif ()
endif ()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
  # Enable Interpreter by default
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_AOT)
  # Enable AOT by default.
  set (WAMR_BUILD_AOT 1)
endif ()

if (NOT DEFINED WAMR_BUILD_JIT)
  # Disable JIT by default.
  set (WAMR_BUILD_JIT 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Enable libc wasi support by default
  set (WAMR_BUILD_LIBC_WASI 1)
endif ()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -pie -fPIE")

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")
# set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion -Wsign-conversion")

if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
  if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
  endif ()
endif ()

# The following flags are to enhance security, but it may impact performance,
# we disable them by default.
#if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
#  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftrapv -D_FORTIFY_SOURCE=2")
#endif ()
#set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong --param ssp-buffer-size=4")
#set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,noexecstack,-z,relro,-z,now")

add_library (iwasm SHARED ${WAMR_RUNTIME_LIB_SOURCE})
if (CMAKE_BUILD_TYPE STREQUAL Release)
target_link_libraries (iwasm ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS} -lm -ldl -landroid -llog -s)
else()
target_link_libraries (iwasm ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS} -lm -ldl -landroid -llog)
endif()

set (distribution_DIR ${CMAKE_BINARY_DIR}/distribution)
set_target_properties (iwasm PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${distribution_DIR}/wasm/lib")

add_custom_command (TARGET iwasm POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_directory "${WAMR_ROOT_DIR}/core/iwasm/include" "${distribution_DIR}/wasm/include/"
        COMMENT "Copying iwasm to output directory")
