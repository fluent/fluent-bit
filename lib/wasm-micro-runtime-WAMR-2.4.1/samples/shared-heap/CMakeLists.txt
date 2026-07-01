# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

include(CheckPIESupported)

if (NOT WAMR_BUILD_PLATFORM STREQUAL "windows")
  project (shared_heap_test)
else()
  project (shared_heap_test C ASM)
endif()

################  runtime settings  ################
string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# WAMR features switch

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
  set (CMAKE_BUILD_TYPE Debug)
endif ()

set (WAMR_BUILD_INTERP 1)
set (WAMR_BUILD_FAST_INTERP 1)
set (WAMR_BUILD_AOT 1)
set (WAMR_BUILD_JIT 0)
set (WAMR_BUILD_LIBC_BUILTIN 1)
set (WAMR_BUILD_LIBC_WASI 0)
set (WAMR_BUILD_SHARED_HEAP 1)
set (WAMR_BUILD_GC_HEAP_VERIFY 1)

if (NOT MSVC)
  # linker flags
  if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
  endif ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")
  if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
    if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
      set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
    endif ()
  endif ()
endif ()

# build out vmlib
set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib STATIC ${WAMR_RUNTIME_LIB_SOURCE})
if (MSVC)
  target_compile_definitions(vmlib PRIVATE WASM_API_EXTERN=)
endif()
target_link_libraries(vmlib ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS} -lm -ldl -lpthread)

################  application related  ################
include_directories(${CMAKE_CURRENT_LIST_DIR}/src)
include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

add_executable (shared_heap_chain_test src/shared_heap_chain.c ${UNCOMMON_SHARED_SOURCE})
add_executable (shared_heap_test src/main.c ${UNCOMMON_SHARED_SOURCE})

check_pie_supported()
set_target_properties (shared_heap_test PROPERTIES POSITION_INDEPENDENT_CODE ON)

if (APPLE)
  set (LIBS vmlib -lm -ldl -lpthread)
else ()
  set (LIBS vmlib -lm -ldl -lpthread -lrt)
endif ()

target_link_libraries (shared_heap_chain_test ${LIBS})
target_link_libraries (shared_heap_test ${LIBS})

add_subdirectory(wasm-apps)

if (WAMR_BUILD_AOT EQUAL 1)
  set (WAMR_COMPILER_DIR ${CMAKE_CURRENT_LIST_DIR}/../../wamr-compiler/build)
  message (CHECK_START "Detecting WAMR_COMPILER at ${WAMR_COMPILER_DIR}")
  find_file (WAMR_COMPILER
    wamrc
    PATHS "${CMAKE_CURRENT_LIST_DIR}/../../wamr-compiler/build"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
  )
  if (WAMR_COMPILER)
    message (CHECK_PASS "found")
  else ()
    message (CHECK_FAIL "not found")
  endif ()
  if (NOT EXISTS ${WAMR_COMPILER})
    message (FATAL_ERROR "Please build wamrc under ${WAMR_ROOT_DIR}/wamr-compiler")
  else ()
    message (STATUS "WAMR_COMPILER is ${WAMR_COMPILER}")
  endif ()

  if (WAMR_BUILD_TARGET STREQUAL "X86_32")
    set (WAMR_COMPILER_FLAGS --enable-shared-heap --target=i386)
    set (WAMR_COMPILER_CHAIN_FLAGS --enable-shared-chain --target=i386)
  else ()
    set (WAMR_COMPILER_FLAGS --enable-shared-heap)
    set (WAMR_COMPILER_CHAIN_FLAGS --enable-shared-chain)
  endif ()

  add_custom_target(
    wasm_to_aot
    ALL
    DEPENDS wasm-apps/test1.wasm wasm-apps/test2.wasm ${WAMR_COMPILER}
    COMMAND ${WAMR_COMPILER} ${WAMR_COMPILER_FLAGS} -o wasm-apps/test1.aot wasm-apps/test1.wasm
    COMMAND ${WAMR_COMPILER} ${WAMR_COMPILER_FLAGS} -o wasm-apps/test2.aot wasm-apps/test2.wasm
    COMMAND ${WAMR_COMPILER} ${WAMR_COMPILER_CHAIN_FLAGS} -o wasm-apps/test1_chain.aot wasm-apps/test1.wasm
    COMMAND ${WAMR_COMPILER} ${WAMR_COMPILER_CHAIN_FLAGS} -o wasm-apps/test2_chain.aot wasm-apps/test2.wasm
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  )
endif()
