# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(how-to-deal-with-import)

include(CMakePrintHelpers)
include(CTest)
include(ExternalProject)
include(FetchContent)

#
# dependencies
#
set(WAMR_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../)
# wasm required headers
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
              ${WARM_ROOT}/${WAMR_ROOT}/wamr-sdk/app/libc-builtin-sysroot/include/pthread.h
              ${CMAKE_CURRENT_LIST_DIR}/wasm/inc
)

# vmlib
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

if (NOT DEFINED WAMR_BUILD_AOT)
  # Enable AOT by default.
  set (WAMR_BUILD_AOT 1)
endif ()
if (NOT DEFINED WAMR_BUILD_INTERP)
    # Disable Interpreter by default
  set (WAMR_BUILD_INTERP 0)
endif ()
set(WAMR_BUILD_JIT 0)
set(WAMR_BUILD_FAST_INTERP 1)
set(WAMR_BUILD_LIB_PTHREAD 1)
set(WAMR_BUILD_LIBC_BUILTIN 1)
set(WAMR_BUILD_LIBC_WASI 1)
set(WAMR_BUILD_SIMD 0)

# compiling and linking flags
if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
endif ()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")

# build out vmlib
set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})
target_link_libraries(vmlib INTERFACE dl m pthread)
if(WAMR_BUILD_AOT EQUAL 1)
  target_compile_definitions(vmlib INTERFACE -DWASM_ENABLE_AOT=1)
else()
  target_compile_definitions(vmlib INTERFACE -DWASM_ENABLE_AOT=0)
endif()

if(WAMR_BUILD_INTERP EQUAL 1)
  target_compile_definitions(vmlib INTERFACE -DWASM_ENABLE_INTERP=1)
else()
  target_compile_definitions(vmlib INTERFACE -DWASM_ENABLE_INTERP=0)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  # ASAN + UBSAN
  target_compile_options(vmlib INTERFACE -fsanitize=address,undefined)
  target_link_options(vmlib INTERFACE -fsanitize=address,undefined)
endif()

# # MSAN
# target_compile_options(vmlib INTERFACE -fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer)
# target_link_options(vmlib INTERFACE -fsanitize=memory)

# wamrc
if(WAMR_BUILD_AOT EQUAL 1 AND WAMR_BUILD_INTERP EQUAL 0)
  ExternalProject_Add(wamrc
    PREFIX            wamrc-build
    SOURCE_DIR        ${WAMR_ROOT}/wamr-compiler
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -S ${WAMR_ROOT}/wamr-compiler -B build
    BUILD_COMMAND     ${CMAKE_COMMAND} --build build --target wamrc
    INSTALL_COMMAND   ${CMAKE_COMMAND} -E copy_if_different build/wamrc ${CMAKE_CURRENT_BINARY_DIR}/wamrc
  )
endif()

#
# host
add_subdirectory(host)
add_custom_target(
  install_host ALL
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ./host/example1 .
  DEPENDS example1
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# TODO: replace it with a find_package()
set(WASI_SDK_DIR /opt/wasi-sdk-19.0/)
set(WASI_TOOLCHAIN_FILE ${WASI_SDK_DIR}/share/cmake/wasi-sdk.cmake)
set(WASI_SYS_ROOT ${WASI_SDK_DIR}/share/wasi-sysroot)

#
# wasm
if(WAMR_BUILD_AOT EQUAL 1 AND WAMR_BUILD_INTERP EQUAL 0)
  ExternalProject_Add(wasm
    PREFIX            wasm-build
    DEPENDS           wamrc
    BUILD_ALWAYS      TRUE
    SOURCE_DIR        ${CMAKE_CURRENT_LIST_DIR}/wasm
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -S ${CMAKE_CURRENT_LIST_DIR}/wasm -B build
                        -DWASI_SDK_PREFIX=${WASI_SDK_DIR}
                        -DCMAKE_TOOLCHAIN_FILE=${WASI_TOOLCHAIN_FILE}
                        -DCMAKE_SYSROOT=${WASI_SYS_ROOT}
                        -DWASM_TO_AOT=ON
                        -DWAMRC_PATH=${CMAKE_CURRENT_BINARY_DIR}/wamrc
                        -DSOCKET_WASI_CMAKE=${WAMR_ROOT}/core/iwasm/libraries/lib-socket/lib_socket_wasi.cmake
    BUILD_COMMAND     ${CMAKE_COMMAND} --build build
    INSTALL_COMMAND   ${CMAKE_COMMAND} --install build --prefix ${CMAKE_CURRENT_BINARY_DIR}
  )
else()
  ExternalProject_Add(wasm
    PREFIX            wasm-build
    BUILD_ALWAYS      TRUE
    SOURCE_DIR        ${CMAKE_CURRENT_LIST_DIR}/wasm
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -S ${CMAKE_CURRENT_LIST_DIR}/wasm -B build
                        -DWASI_SDK_PREFIX=${WASI_SDK_DIR}
                        -DCMAKE_TOOLCHAIN_FILE=${WASI_TOOLCHAIN_FILE}
                        -DCMAKE_SYSROOT=${WASI_SYS_ROOT}
                        -DSOCKET_WASI_CMAKE=${WAMR_ROOT}/core/iwasm/libraries/lib-socket/lib_socket_wasi.cmake
    BUILD_COMMAND     ${CMAKE_COMMAND} --build build
    INSTALL_COMMAND   ${CMAKE_COMMAND} --install build --prefix ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

#
# Test
#
add_test(
  NAME run_example1
  COMMAND ./example1
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
