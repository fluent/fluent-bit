# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

include(CheckPIESupported)

project(socket_api_sample)

#######################################
## Detect toolchain
#######################################
message(CHECK_START "Detecting WASI-SDK at /opt/wasi-sdk")
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

if(NOT EXISTS ${WASI_SDK_DIR})
  message(FATAL_ERROR "Please install WASI-SDK under /opt/wasi-sdk")
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

if(WASI_TOOLCHAIN_FILE-NOTFOUND)
  message(FATAL_ERROR "Can not find wasi-sdk.cmake under ${WASI_SDK_DIR}")
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

if(WASI_SYS_ROOT-NOTFOUND)
  message(FATAL_ERROR "Can not find wasi-sysroot/ under ${WASI_SDK_DIR}")
endif()

message(STATUS "WASI_SDK_DIR is ${WASI_SDK_DIR}")
message(STATUS "WASI_TOOLCHAIN_FILE is ${WASI_TOOLCHAIN_FILE}")
message(STATUS "WASI_SYS_ROOT is ${WASI_SYS_ROOT}")

###############################################################
## Build socket applications of wasm version and native version
###############################################################
include(ExternalProject)

ExternalProject_Add(wasm-app
  SOURCE_DIR        ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src
  UPDATE_COMMAND    ""
  PATCH_COMMAND     ""
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E copy
                      ${CMAKE_CURRENT_SOURCE_DIR}/../../wamr-sdk/app/libc-builtin-sysroot/include/pthread.h
                      ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/inc
                    && ${CMAKE_COMMAND}
                      -DWASI_SDK_PREFIX=${WASI_SDK_DIR}
                      -DCMAKE_TOOLCHAIN_FILE=${WASI_TOOLCHAIN_FILE}
                      -DCMAKE_SYSROOT=${WASI_SYS_ROOT}
                      ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src
  BUILD_COMMAND     ${CMAKE_COMMAND} --build .
  INSTALL_COMMAND   ${CMAKE_COMMAND} -E copy
                      addr_resolve.wasm ${CMAKE_BINARY_DIR}
                      tcp_client.wasm ${CMAKE_BINARY_DIR}
                      tcp_server.wasm ${CMAKE_BINARY_DIR}
                      send_recv.wasm ${CMAKE_BINARY_DIR}
                      socket_opts.wasm ${CMAKE_BINARY_DIR}
                      udp_client.wasm ${CMAKE_BINARY_DIR}
                      udp_server.wasm ${CMAKE_BINARY_DIR}
                      multicast_client.wasm ${CMAKE_BINARY_DIR}
                      multicast_server.wasm ${CMAKE_BINARY_DIR}
                      timeout_client.wasm ${CMAKE_BINARY_DIR}
                      timeout_server.wasm ${CMAKE_BINARY_DIR}
)

add_executable(tcp_server ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/tcp_server.c)
target_link_libraries(tcp_server pthread)

add_executable(tcp_client ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/tcp_client.c)

add_executable(send_recv ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/send_recv.c)
target_link_libraries(send_recv pthread)

add_executable(addr_resolve ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/addr_resolve.c)

add_executable(socket_opts ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/socket_opts.c)

add_executable(udp_client ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/udp_client.c)

add_executable(udp_server ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/udp_server.c)

add_executable(multicast_client ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/multicast_client.c)

add_executable(multicast_server ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/multicast_server.c)

add_executable(timeout_client ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/timeout_client.c)

add_executable(timeout_server ${CMAKE_CURRENT_SOURCE_DIR}/wasm-src/timeout_server.c)

############################################
## Build iwasm with wasi and pthread support
############################################
string (TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

# Reset linker flags
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR features

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
set(WAMR_BUILD_FAST_INTERP 1)
set(WAMR_BUILD_AOT 1)
set(WAMR_BUILD_JIT 0)
set(WAMR_BUILD_LIBC_BUILTIN 1)
set(WAMR_BUILD_LIBC_WASI 1)
set(WAMR_BUILD_LIB_PTHREAD 1)

# compiling and linking flags
if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
endif ()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")

# build vmlib static lib
set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

# build iwasm
include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)
set (RUNTIME_SOURCE_ALL
    ${CMAKE_CURRENT_LIST_DIR}/../../product-mini/platforms/linux/main.c
    ${UNCOMMON_SHARED_SOURCE}
)
add_executable (iwasm ${RUNTIME_SOURCE_ALL})
check_pie_supported()
set_target_properties (iwasm PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(iwasm vmlib -lpthread -lm -ldl)
