# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.9)

if (NOT WAMR_BUILD_PLATFORM STREQUAL "windows")
  project(c-api)
else()
  project (c-api C ASM)
  enable_language (ASM_MASM)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 14)
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

if(NOT DEFINED WAMR_BUILD_INTERP)
  set(WAMR_BUILD_INTERP 1)
endif()

if(NOT DEFINED WAMR_BUILD_AOT)
  set(WAMR_BUILD_AOT 0)
endif()

if(NOT DEFINED WAMR_BUILD_JIT)
  set(WAMR_BUILD_JIT 0)
endif()

set(WAMR_BUILD_LIBC_BUILTIN 1)
set(WAMR_BUILD_LIBC_WASI 0)
set(WAMR_BUILD_MULTI_MODULE 1)
set(WAMR_BUILD_DUMP_CALL_STACK 1)
set(WAMR_BUILD_REF_TYPES 1)

if(NOT DEFINED WAMR_BUILD_FAST_INTERP)
  set(WAMR_BUILD_FAST_INTERP 1)
endif()

if (NOT MSVC)
  # compiling and linking flags
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -fPIE")
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
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib STATIC ${WAMR_RUNTIME_LIB_SOURCE})
if (MSVC)
  target_compile_definitions(vmlib PRIVATE WASM_API_EXTERN=)
endif()
target_link_libraries (vmlib ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS} -lm -ldl -lpthread)
################################################

################  application related  ################
## locate wat2wasm
find_program(WAT2WASM
  wat2wasm
  PATHS /opt/wabt/bin
  REQUIRED
)

if(NOT WAT2WASM)
  message(SEND_ERROR "can not find wat2wasm")
endif()

if(${WAMR_BUILD_AOT} EQUAL 1)
  ## locate wamrc
  find_program(WAMRC
    wamrc
    PATHS ${WAMR_ROOT_DIR}/wamr-compiler/build/
  )

  if(NOT WAMRC)
    message(SEND_ERROR "can not find wamrc.  refer to \
        https://github.com/bytecodealliance/wasm-micro-runtime#build-wamrc-aot-compiler"
    )
  endif()
endif()
include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

set(MM_UTIL src/utils/multi_module_utils.c)
# build executable for each .c
set(EXAMPLES
  callback
  callback_chain
  empty_imports
  global
  hello
  hostref
  memory
  reflect
  table
  trap
)

foreach(EX ${EXAMPLES})
  set(SRC ${CMAKE_CURRENT_LIST_DIR}/src/${EX}.c)

  add_executable(${EX} ${SRC} ${UNCOMMON_SHARED_SOURCE} ${MM_UTIL})
  target_include_directories(${EX} PRIVATE ${UNCOMMON_SHARED_DIR})
  target_link_libraries(${EX} vmlib -lpthread -lm)
  if (MSVC)
    target_compile_definitions(${EX} PRIVATE WASM_API_EXTERN=)
  endif()

  # wat to wasm
  set(WAT ${CMAKE_CURRENT_LIST_DIR}/src/${EX}.wat)

  add_custom_target(${EX}_WASM
    COMMAND ${WAT2WASM} ${WAT} --enable-reference-types -o ${PROJECT_BINARY_DIR}/${EX}.wasm
    DEPENDS ${WAT}
    BYPRODUCTS ${PROJECT_BINARY_DIR}/${EX}.wasm
    VERBATIM
  )
  add_dependencies(${EX} ${EX}_WASM)

  # generate .aot file
  if(${WAMR_BUILD_AOT} EQUAL 1)
    add_custom_target(${EX}_AOT
      COMMAND ${WAMRC} -o ${PROJECT_BINARY_DIR}/${EX}.aot
        ${PROJECT_BINARY_DIR}/${EX}.wasm
      DEPENDS ${EX}_WASM
      BYPRODUCTS ${PROJECT_BINARY_DIR}/${EX}.aot
      VERBATIM
      COMMENT "generate a aot file ${PROJECT_BINARY_DIR}/${EX}.aot"
    )
    add_dependencies(${EX} ${EX}_AOT)
  endif()
endforeach()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  find_program(VALGRIND
    valgrind
    REQUIRED
  )

  if(VALGRIND)
    foreach(EX ${EXAMPLES})
      add_custom_target(${EX}_LEAK_TEST
        COMMAND ${VALGRIND} --tool=memcheck --leak-check=yes ./${EX}
        DEPENDS ${EX} ${EX}_WASM
        VERBATIM
        COMMENT "run a leak check on ${EX}"
      )
    endforeach()
  endif (VALGRIND)
endif (CMAKE_BUILD_TYPE STREQUAL "Debug")
