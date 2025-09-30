# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

include(CheckPIESupported)

project(native_lib)

################ runtime settings  ##############
string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# WAMR features switch

# Set WAMR_BUILD_TARGET, currently values supported are:
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
  set (CMAKE_BUILD_TYPE Release)
endif ()

set (WAMR_BUILD_INTERP 1)
set (WAMR_BUILD_AOT 1)
set (WAMR_BUILD_JIT 0)
set (WAMR_BUILD_LIBC_BUILTIN 1)
set (WAMR_BUILD_FAST_INTERP 1)

# compiling and linking flags
if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
endif ()
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")

# build out libiwasm
set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

# Note: we build libiwasm as a shared library here so that it can be
# shared between iwasm and native libraries.
add_library(libiwasm SHARED ${WAMR_RUNTIME_LIB_SOURCE})
set_target_properties (libiwasm PROPERTIES OUTPUT_NAME iwasm)

################ wamr runtime ###################
include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

set (RUNTIME_SOURCE_ALL
    ${WAMR_ROOT_DIR}/product-mini/platforms/posix/main.c
    ${UNCOMMON_SHARED_SOURCE}
)

add_executable (iwasm ${RUNTIME_SOURCE_ALL})

check_pie_supported()
set_target_properties (iwasm PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(iwasm libiwasm -lpthread -lm -ldl)

################ native libraries ###############
add_library (test_add SHARED test_add.c)
add_library (test_sqrt SHARED test_sqrt.c)
add_library (test_hello SHARED test_hello.c)
# Note: Unlike simpler examples above, test_hello2 directly uses
# the API provided by the libiwasm library.
add_library (test_hello2 SHARED test_hello2.c)
target_link_libraries(test_hello2 libiwasm)

################ wasm application ###############
add_subdirectory(wasm-app)
