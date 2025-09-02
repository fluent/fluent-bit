# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

include(CheckPIESupported)

project(multi_module)

################  runtime settings  ################
string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

# Resetdefault linker flags
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

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
  set (CMAKE_BUILD_TYPE Release)
endif ()

set(WAMR_BUILD_INTERP 1)
if (NOT DEFINED WAMR_BUILD_AOT)
  set(WAMR_BUILD_AOT 0)
endif ()
if (NOT DEFINED WAMR_BUILD_JIT)
  set(WAMR_BUILD_JIT 0)
endif ()
if (NOT DEFINED WAMR_BUILD_DUMP_CALL_STACK)
  set(WAMR_BUILD_DUMP_CALL_STACK 0)
endif ()
if (NOT DEFINED WAMR_BUILD_GC)
  set(WAMR_BUILD_GC 0)
endif ()
set(WAMR_BUILD_SIMD 1)
set(WAMR_BUILD_REF_TYPES 1)
set(WAMR_BUILD_LIBC_BUILTIN 1)
set(WAMR_BUILD_LIBC_WASI 1)
set(WAMR_BUILD_MULTI_MODULE 1)

# compiling and linking flags
if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
endif ()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")
if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
  if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
  endif ()
endif ()

# build out vmlib
set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib STATIC ${WAMR_RUNTIME_LIB_SOURCE})
################################################

################  application related  ################

################ WASM MODULES
include(ExternalProject)

message(CHECK_START "Detecting WASI-SDK")
if(NOT (DEFINED WASI_SDK_DIR OR DEFINED CACHE{WASI_SDK_DIR}))
  find_path(WASI_SDK_PARENT
    wasi-sdk
    PATHS /opt
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
  )
  if(WASI_SDK_PARENT)
    set(WASI_SDK_DIR ${WASI_SDK_PARENT}/wasi-sdk)
  endif()
endif()
if(WASI_SDK_DIR)
  message(CHECK_PASS "found")
else()
  message(CHECK_FAIL "not found")
endif()

message(CHECK_START "Detecting WASI_TOOLCHAIN_FILE at ${WASI_SDK_DIR}")
find_file(WASI_TOOLCHAIN_FILE
  wasi-sdk.cmake
  PATHS "${WASI_SDK_DIR}/share/cmake"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH
)
if(WASI_TOOLCHAIN_FILE)
  message(CHECK_PASS "found")
else()
  message(CHECK_FAIL "not found")
endif()

message(CHECK_START "Detecting WASI_SYS_ROOT at ${WASI_SDK_DIR}")
find_path(WASI_SYS_ROOT
  wasi-sysroot
  PATHS "${WASI_SDK_DIR}/share"
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH
)
if(WASI_SYS_ROOT)
  message(CHECK_PASS "found")
  set(WASI_SYS_ROOT ${WASI_SYS_ROOT}/wasi-sysroot)
else()
  message(CHECK_FAIL "not found")
endif()

if((NOT EXISTS ${WASI_SDK_DIR}) OR (NOT EXISTS ${WASI_TOOLCHAIN_FILE}) OR (NOT EXISTS ${WASI_SYS_ROOT}))
  message(FATAL_ERROR "Please set the absolute path of wasi-sdk with \'cmake -DWASI_SDK_DIR=XXX\'")
else()
  message(STATUS "WASI_SDK_DIR is ${WASI_SDK_DIR}")
  message(STATUS "WASI_TOOLCHAIN_FILE is ${WASI_TOOLCHAIN_FILE}")
  message(STATUS "WASI_SYS_ROOT is ${WASI_SYS_ROOT}")
endif()

# .c -> .wasm
ExternalProject_Add(WASM_MODULE
  SOURCE_DIR         ${CMAKE_CURRENT_SOURCE_DIR}/wasm-apps
  BUILD_ALWAYS TRUE
  UPDATE_COMMAND     ""
  PATCH_COMMAND      ""
  CONFIGURE_COMMAND  ${CMAKE_COMMAND}
                       -DWASI_SDK_PREFIX=${WASI_SDK_DIR}
                       -DCMAKE_TOOLCHAIN_FILE=${WASI_TOOLCHAIN_FILE}
                       -DCMAKE_SYSROOT=${WASI_SYS_ROOT}
                       -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                       -S ${CMAKE_CURRENT_SOURCE_DIR}/wasm-apps
  BUILD_COMMAND      ${CMAKE_COMMAND} --build .
  INSTALL_COMMAND    ${CMAKE_COMMAND} -E copy
                       ./mA.wasm ${CMAKE_BINARY_DIR}
                       ./mB.wasm ${CMAKE_BINARY_DIR}
                       ./mC.wasm ${CMAKE_BINARY_DIR}
                       ./mD.wasm ${CMAKE_BINARY_DIR}
                       ./mE.wasm ${CMAKE_BINARY_DIR}
)

################ WASM MODULES TO AOT
if (WAMR_BUILD_AOT EQUAL 1)
  set(WAMR_COMPILER_DIR ${CMAKE_CURRENT_LIST_DIR}/../../wamr-compiler/build)
  message(CHECK_START "Detecting WAMR_COMPILER at ${WAMR_COMPILER_DIR}")
  find_file(WAMR_COMPILER
    wamrc
    PATHS "${CMAKE_CURRENT_LIST_DIR}/../../wamr-compiler/build"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
  )
  if(WAMR_COMPILER)
    message(CHECK_PASS "found")
  else()
    message(CHECK_FAIL "not found")
  endif()
  if((NOT EXISTS ${WAMR_COMPILER}) )
    message(FATAL_ERROR "Please build wamrc under the path=${WAMR_ROOT_DIR}/wamr-compiler/ ")
  else()
    message(STATUS "WAMR_COMPILER is ${WAMR_COMPILER}")
  endif()

  if (WAMR_BUILD_DUMP_CALL_STACK EQUAL 1)
    list(APPEND WAMR_AOT_COMPILE_OPTIONS "--enable-dump-call-stack")
  endif ()
  if (WAMR_BUILD_GC EQUAL 1)
    list(APPEND WAMR_AOT_COMPILE_OPTIONS "--enable-gc")
  endif ()

  add_custom_target(
    wasm_to_aot
    ALL
    DEPENDS
    WASM_MODULE ${WAMR_COMPILER}
    COMMAND
    ${WAMR_COMPILER} ${WAMR_AOT_COMPILE_OPTIONS} -o mA.aot ./mA.wasm
    COMMAND
    ${WAMR_COMPILER} ${WAMR_AOT_COMPILE_OPTIONS} -o mB.aot ./mB.wasm
    COMMAND
    ${WAMR_COMPILER} ${WAMR_AOT_COMPILE_OPTIONS} -o mC.aot ./mC.wasm
    WORKING_DIRECTORY
    ${CMAKE_BINARY_DIR}
  )
endif()

################ NATIVE
include_directories(${CMAKE_CURRENT_LIST_DIR}/src)
include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

add_executable(multi_module src/main.c ${UNCOMMON_SHARED_SOURCE})

add_dependencies(multi_module vmlib WASM_MODULE)

check_pie_supported()
set_target_properties (multi_module PROPERTIES POSITION_INDEPENDENT_CODE ON)

# libraries
target_link_libraries(multi_module PRIVATE vmlib -lpthread -lm)
