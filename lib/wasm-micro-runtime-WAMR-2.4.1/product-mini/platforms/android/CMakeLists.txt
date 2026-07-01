# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

if (NOT DEFINED WAMR_BUILD_TARGET)
  message (FATAL_ERROR "WAMR_BUILD_TARGET isn't set")
endif ()

if (NOT (WAMR_BUILD_TARGET STREQUAL "X86_64"
         OR WAMR_BUILD_TARGET STREQUAL "X86_32"
         OR WAMR_BUILD_TARGET MATCHES "AARCH64.*"
         OR WAMR_BUILD_TARGET MATCHES "ARM.*"
         OR WAMR_BUILD_TARGET MATCHES "RISCV64.*"))
  message (FATAL_ERROR "Unsupported build target platform ${WAMR_BUILD_TARGET}!")
endif ()

if (NOT DEFINED ANDROID_ABI)
  if (WAMR_BUILD_TARGET STREQUAL "X86_64")
    set (ANDROID_ABI "x86_64")
  elseif (WAMR_BUILD_TARGET STREQUAL "X86_32")
    set (ANDROID_ABI "x86")
  elseif (WAMR_BUILD_TARGET MATCHES "AARCH64.*")
    set (ANDROID_ABI "arm64-v8a")
  elseif (WAMR_BUILD_TARGET MATCHES "ARM.*")
    set (ANDROID_ABI "armeabi-v7a")
  else ()
    set (ANDROID_ABI "riscv64")
  endif ()
endif ()

if (NOT DEFINED ANDROID_LD)
  set (ANDROID_LD lld)
endif ()

if (NOT DEFINED ANDROID_PLATFORM)
  set (ANDROID_PLATFORM 24)
endif ()

# https://android.googlesource.com/platform/ndk/+/master/build/cmake/android.toolchain.cmake
set (CMAKE_TOOLCHAIN_FILE "$ENV{ANDROID_NDK_LATEST_HOME}/build/cmake/android.toolchain.cmake")
set (ANDROID_SDK $ENV{ANDROID_HOME})
set (ANDROID_NDK $ENV{ANDROID_NDK_LATEST_HOME})

project (iwasm)

set (WAMR_BUILD_PLATFORM "android")

set (CMAKE_VERBOSE_MAKEFILE ON)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release)
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
  # Enable Interpreter by default
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
  # Enable fast interpreter
  set (WAMR_BUILD_FAST_INTERP 1)
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

if (NOT DEFINED WAMR_BUILD_MULTI_MODULE)
  # Disable multiple modules by default
  set (WAMR_BUILD_MULTI_MODULE 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIB_PTHREAD)
  # Disable pthread library by default
  set (WAMR_BUILD_LIB_PTHREAD 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIB_WASI_THREADS)
  # Disable wasi threads library by default
  set (WAMR_BUILD_LIB_WASI_THREADS 0)
endif()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

set_version_info (vmlib)

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
set_version_info (iwasm)

add_custom_command (TARGET iwasm POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_directory "${WAMR_ROOT_DIR}/core/iwasm/include" "${distribution_DIR}/wasm/include/"
        COMMENT "Copying iwasm to output directory")
