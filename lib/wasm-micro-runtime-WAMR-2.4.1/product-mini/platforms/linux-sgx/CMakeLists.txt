# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project (iwasm)

set (WAMR_BUILD_PLATFORM "linux-sgx")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR_BUILD_TARGET
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
    if (NOT DEFINED WAMR_BUILD_SIMD)
      # Enable SIMD by default in 64-bit platform
      set (WAMR_BUILD_SIMD 1)
    endif ()
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
  # Enable AOT by default
  # Please install Intel SGX SDKv2.8 or later.
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

if (NOT DEFINED WAMR_BUILD_LIB_RATS)
  # Disable lib rats support by default
  set (WAMR_BUILD_LIB_RATS 0)
endif()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
  # Enable fast interpreter
  set (WAMR_BUILD_FAST_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_MULTI_MODULE)
  # Enable multiple modules
  set (WAMR_BUILD_MULTI_MODULE 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIB_PTHREAD)
  # Enable pthread library by default
  set (WAMR_BUILD_LIB_PTHREAD 1)
endif ()

if (NOT DEFINED WAMR_BUILD_SIMD)
  # Disable SIMD by default
  set (WAMR_BUILD_SIMD 0)
endif ()

if (NOT DEFINED WAMR_BUILD_SGX_IPFS)
  # Disable SGX IPFS by default
  set (WAMR_BUILD_SGX_IPFS 0)
endif ()

if (NOT DEFINED WAMR_BUILD_STATIC_PGO)
  # Disable static PGO by default
  set (WAMR_BUILD_STATIC_PGO 0)
endif ()

if (NOT DEFINED WAMR_BUILD_REF_TYPES)
  # Enable reference types by default
  set (WAMR_BUILD_REF_TYPES 1)
endif ()

set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -ffunction-sections -fdata-sections \
                                     -Wall -Wno-unused-parameter -Wno-pedantic \
                                     -nostdinc -fvisibility=hidden -fpie" )

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})
set_version_info (vmlib)

add_custom_command (
             OUTPUT libvmlib_untrusted.a
             COMMAND mkdir -p untrusted && cd untrusted &&
                     ${CMAKE_C_COMPILER} -c ${PLATFORM_SHARED_SOURCE_UNTRUSTED}
             COMMAND ${CMAKE_AR} rc libvmlib_untrusted.a untrusted/*.o)

add_custom_target (vmlib_untrusted ALL DEPENDS libvmlib_untrusted.a)

if ((WAMR_BUILD_STATIC_PGO EQUAL 1) AND (WAMR_BUILD_AOT EQUAL 1))
    execute_process(
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_STATIC_PGO = 0/WAMR_BUILD_STATIC_PGO = 1/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
else()
    execute_process(
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_STATIC_PGO = 1/WAMR_BUILD_STATIC_PGO = 0/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
endif()

if (DEFINED WAMR_BUILD_GLOBAL_HEAP_POOL)
  execute_process(
      COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_GLOBAL_HEAP_POOL = .*/WAMR_BUILD_GLOBAL_HEAP_POOL = ${WAMR_BUILD_GLOBAL_HEAP_POOL}/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
      OUTPUT_VARIABLE cmdOutput
  )
  if (DEFINED WAMR_BUILD_GLOBAL_HEAP_SIZE)
    execute_process(
      COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_GLOBAL_HEAP_SIZE = .*/WAMR_BUILD_GLOBAL_HEAP_SIZE = ${WAMR_BUILD_GLOBAL_HEAP_SIZE}/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
      OUTPUT_VARIABLE cmdOutput
    )
  endif()
endif()

if (WAMR_BUILD_LIB_RATS EQUAL 1)
    execute_process(
        COMMAND bash -c "sed -i -E 's/^#define WASM_ENABLE_LIB_RATS 0/#define WASM_ENABLE_LIB_RATS 1/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Enclave/Enclave.edl"
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_LIB_RATS = 0/WAMR_BUILD_LIB_RATS = 1/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
else()
    execute_process(
        COMMAND bash -c "sed -i -E 's/^#define WASM_ENABLE_LIB_RATS 1/#define WASM_ENABLE_LIB_RATS 0/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Enclave/Enclave.edl"
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_LIB_RATS = 1/WAMR_BUILD_LIB_RATS = 0/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
endif()

if (WAMR_BUILD_SGX_IPFS EQUAL 1)
    execute_process(
        COMMAND bash -c "sed -i -E 's/^#define WASM_ENABLE_SGX_IPFS 0/#define WASM_ENABLE_SGX_IPFS 1/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Enclave/Enclave.edl"
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_SGX_IPFS = 0/WAMR_BUILD_SGX_IPFS = 1/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
else()
    execute_process(
        COMMAND bash -c "sed -i -E 's/^#define WASM_ENABLE_SGX_IPFS 1/#define WASM_ENABLE_SGX_IPFS 0/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Enclave/Enclave.edl"
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_SGX_IPFS = 1/WAMR_BUILD_SGX_IPFS = 0/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
endif()

if (WAMR_BUILD_LIBC_WASI EQUAL 1)
    execute_process(
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_LIBC_WASI = 0/WAMR_BUILD_LIBC_WASI = 1/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
else()
    execute_process(
        COMMAND bash -c "sed -i -E 's/^WAMR_BUILD_LIBC_WASI = 1/WAMR_BUILD_LIBC_WASI = 0/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Makefile"
        OUTPUT_VARIABLE cmdOutput
    )
endif()

if (WAMR_BUILD_SPEC_TEST EQUAL 1)
    execute_process(
        COMMAND bash -c "sed -i -E 's/<ReservedMemMaxSize>0x1000000<\\/ReservedMemMaxSize>/<ReservedMemMaxSize>0x8000000<\\/ReservedMemMaxSize>/g' ${CMAKE_CURRENT_SOURCE_DIR}/enclave-sample/Enclave/Enclave.config.xml"
        OUTPUT_VARIABLE cmdOutput
    )
endif()
