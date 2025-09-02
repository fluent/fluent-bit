# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

if(ESP_PLATFORM)
  include (${COMPONENT_DIR}/build-scripts/esp-idf/wamr/CMakeLists.txt)
  return()
endif()

project (iwasm LANGUAGES C)

set(CMAKE_CXX_STANDARD 17)

set (CMAKE_VERBOSE_MAKEFILE OFF)

if (NOT DEFINED WAMR_BUILD_PLATFORM)
  string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
endif ()

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

set (CMAKE_C_STANDARD 99)

# Set WAMR_BUILD_TARGET, currently values supported:
# "X86_64", "AMD_64", "X86_32", "AARCH64[sub]", "ARM[sub]", "THUMB[sub]",
# "MIPS", "XTENSA", "RISCV64[sub]", "RISCV32[sub]"
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
    set (WAMR_BUILD_TARGET "AARCH64")
  elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
    set (WAMR_BUILD_TARGET "RISCV64")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
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

if (NOT DEFINED WAMR_BUILD_FAST_JIT)
  # Disable Fast JIT by default
  set (WAMR_BUILD_FAST_JIT 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Enable libc wasi support by default
  set (WAMR_BUILD_LIBC_WASI 1)
endif ()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
  # Enable fast interpreter
  set (WAMR_BUILD_FAST_INTERP 1)
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
endif ()

if (NOT DEFINED WAMR_BUILD_COPY_CALL_STACK)
  # Disable copy callstack by default
  set (WAMR_BUILD_COPY_CALL_STACK 0)
endif()

if (NOT DEFINED WAMR_BUILD_MINI_LOADER)
  # Disable wasm mini loader by default
  set (WAMR_BUILD_MINI_LOADER 0)
endif ()

if (NOT DEFINED WAMR_BUILD_SIMD)
  # Enable SIMD by default
  set (WAMR_BUILD_SIMD 1)
endif ()

if (NOT DEFINED WAMR_BUILD_REF_TYPES)
  # Enable reference types by default
  set (WAMR_BUILD_REF_TYPES 1)
endif ()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

if (NOT WIN32)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security \
                                       -ffunction-sections -fdata-sections \
                                       -Wno-unused-parameter -Wno-pedantic \
                                       -fvisibility=hidden")
  # Remove the extra spaces for better make log
  string (REGEX REPLACE "  *" " " CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wformat -Wformat-security -Wno-unused")
endif()

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

include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

set (THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library (vmlib ${WAMR_RUNTIME_LIB_SOURCE})
set_target_properties (vmlib PROPERTIES OUTPUT_NAME iwasm)
target_include_directories(vmlib INTERFACE
  $<BUILD_INTERFACE:${WAMR_ROOT_DIR}/core/iwasm/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries (vmlib PUBLIC ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS} -lm -ldl ${CMAKE_THREAD_LIBS_INIT})
if (WAMR_BUILD_WASM_CACHE EQUAL 1)
  target_link_libraries(vmlib INTERFACE boringssl_crypto)
endif ()

if (MINGW)
  target_link_libraries(vmlib INTERFACE -lWs2_32 -lwsock32)
  target_link_libraries(vmlib PRIVATE ws2_32)
endif ()

if (WIN32)
  target_link_libraries(vmlib PRIVATE ntdll)
endif()

set (WAMR_PUBLIC_HEADERS
  ${WAMR_ROOT_DIR}/core/iwasm/include/wasm_c_api.h
  ${WAMR_ROOT_DIR}/core/iwasm/include/wasm_export.h
  ${WAMR_ROOT_DIR}/core/iwasm/include/lib_export.h
)
set_target_properties (vmlib PROPERTIES PUBLIC_HEADER "${WAMR_PUBLIC_HEADERS}")

set_version_info (vmlib)

install (TARGETS vmlib
  EXPORT iwasmTargets
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include
)

install_iwasm_package ()
