# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

include(CheckPIESupported)

if (NOT WAMR_BUILD_PLATFORM STREQUAL "windows")
  project(ref-types)
else()
  project (ref-types C ASM)
endif()

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

if(NOT DEFINED WAMR_BUILD_INTERP)
  set(WAMR_BUILD_INTERP 1)
endif()

if(NOT DEFINED WAMR_BUILD_AOT)
  set(WAMR_BUILD_AOT 0)
endif()

if(NOT DEFINED WAMR_BUILD_JOT)
  set(WAMR_BUILD_JIT 0)
endif()

if(NOT DEFINED WAMR_BUILD_FAST_INTERP)
  set(WAMR_BUILD_FAST_INTERP 1)
endif()

if(NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  set(WAMR_BUILD_LIBC_BUILTIN 1)
endif()

# Enable reference-types feature
set(WAMR_BUILD_REF_TYPES 1)

if (NOT MSVC)
  # compiling and linking flags
  if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
  endif ()
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")
  if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
    if (NOT (CMAKE_C_COMPILER MATCHES ".*clang.*" OR CMAKE_C_COMPILER_ID MATCHES ".*Clang"))
      set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mindirect-branch-register")
    endif ()
  endif ()
endif()
# build out vmlib
set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
set(WAMRC ${WAMR_ROOT_DIR}/wamr-compiler/build/wamrc)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib STATIC ${WAMR_RUNTIME_LIB_SOURCE})
if (MSVC)
  target_compile_definitions(vmlib PRIVATE WASM_API_EXTERN=)
endif()

################  application related  ################
## locate wat2wasm
find_program(WAT2WASM
  wat2wasm
  PATHS /opt/wabt/bin
  REQUIRED
)

if(NOT WAT2WASM)
  message(SEND_ERROR "can not find wat2wasm")
else ()
  execute_process(COMMAND ${WAT2WASM} --version
                  OUTPUT_VARIABLE WAT2WASM_VERSION_OUTPUT)
  string(STRIP ${WAT2WASM_VERSION_OUTPUT} WAT2WASM_VERSION)
  message("-- Found wat2wasm ${WAT2WASM_VERSION}")
endif()

if (${WAT2WASM_VERSION} VERSION_LESS 1.0.26)
  set(WAT2WASM_FLAGS "--enable-reference-types")
endif ()

include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

add_executable(hello src/hello.c ${UNCOMMON_SHARED_SOURCE})

check_pie_supported()
set_target_properties (hello PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(hello PRIVATE ${UNCOMMON_SHARED_DIR})

target_link_libraries(hello vmlib -lpthread -lm)

if (MSVC)
  target_compile_definitions(hello PRIVATE WASM_API_EXTERN=)
endif()

# wat to wasm
file(GLOB WAT_FILE src/hello.wat)
add_custom_target(hello_wasm ALL
  COMMAND ${WAT2WASM} ${WAT_FILE} ${WAT2WASM_FLAGS} -o ${PROJECT_BINARY_DIR}/hello.wasm
  DEPENDS ${WAT_FILE}
  BYPRODUCTS ${PROJECT_BINARY_DIR}/hello.wasm
  VERBATIM
  SOURCES ${WAT_FILE}
)
