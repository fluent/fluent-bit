# Copyright (c) 2022 Intel Corporation
# Copyright (c) 2020-2021 Alibaba Cloud
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(sgx-ra)

################ runtime settings  ##############
set (WAMR_BUILD_PLATFORM "linux-sgx")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR_BUILD_TARGET
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
  set (CMAKE_BUILD_TYPE Release)
endif ()

set (WAMR_BUILD_INTERP 1)
set (WAMR_BUILD_AOT 1)
set (WAMR_BUILD_JIT 0)
set (WAMR_BUILD_LIBC_BUILTIN 1)
set (WAMR_BUILD_LIBC_WASI 1)
set (WAMR_BUILD_LIB_PTHREAD 1)
set (WAMR_BUILD_FAST_INTERP 1)
set (WAMR_BUILD_LIB_RATS 1)

# compiling and linking flags
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -ffunction-sections -fdata-sections \
                                     -Wall -Wno-unused-parameter -Wno-pedantic \
                                     -nostdinc -fvisibility=hidden -fpie" )

# build out vmlib
set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
set (SGX_PLATFORM_DIR ${WAMR_ROOT_DIR}/product-mini/platforms/linux-sgx)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})

add_custom_command (
             OUTPUT libvmlib_untrusted.a
             COMMAND mkdir -p untrusted && cd untrusted &&
                     ${CMAKE_C_COMPILER} -c ${PLATFORM_SHARED_SOURCE_UNTRUSTED}
             COMMAND ${CMAKE_AR} rc libvmlib_untrusted.a untrusted/*.o)

add_custom_target (vmlib_untrusted ALL DEPENDS libvmlib_untrusted.a)

execute_process (
    COMMAND bash -c "sed -i -E 's/^#define WASM_ENABLE_LIB_RATS 0/#define WASM_ENABLE_LIB_RATS 1/g' ${SGX_PLATFORM_DIR}/enclave-sample/Enclave/Enclave.edl"
    COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_LIB_RATS = 0/WAMR_BUILD_LIB_RATS = 1/g' ${SGX_PLATFORM_DIR}/enclave-sample/Makefile"
    OUTPUT_VARIABLE cmdOutput
)

################ wamr runtime ###################
add_custom_target (
              iwasm ALL
              DEPENDS vmlib_untrusted vmlib_untrusted vmlib
              COMMAND make -C ${SGX_PLATFORM_DIR}/enclave-sample clean
              COMMAND make -C  ${SGX_PLATFORM_DIR}/enclave-sample SGX_MODE=HW SGX_DEBUG=1 VMLIB_BUILD_DIR=${CMAKE_BINARY_DIR}
              COMMAND ${CMAKE_COMMAND} -E copy ${SGX_PLATFORM_DIR}/enclave-sample/enclave.signed.so ${CMAKE_BINARY_DIR}
              COMMAND ${CMAKE_COMMAND} -E copy ${SGX_PLATFORM_DIR}/enclave-sample/iwasm ${CMAKE_BINARY_DIR}
              COMMAND make -C ${SGX_PLATFORM_DIR}/enclave-sample clean)

################ wasm application ###############
add_subdirectory(wasm-app)
