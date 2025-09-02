# Copyright (C) 2025 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(CUSTOM_MUTATOR EQUAL 1)
  add_compile_definitions(CUSTOM_MUTATOR)
endif()

# Set default build options with the ability to override from the command line
if(NOT WAMR_BUILD_INTERP)
  set(WAMR_BUILD_INTERP 1)
endif()

if(NOT WAMR_BUILD_AOT)
  set(WAMR_BUILD_AOT 1)
endif()

if(NOT WAMR_BUILD_JIT)
  set(WAMR_BUILD_JIT 0)
endif()

if(NOT WAMR_BUILD_LIBC_BUILTIN)
  set(WAMR_BUILD_LIBC_BUILTIN 0)
endif()

if(NOT WAMR_BUILD_LIBC_WASI)
  set(WAMR_BUILD_LIBC_WASI 1)
endif()

if(NOT WAMR_BUILD_FAST_INTERP)
  set(WAMR_BUILD_FAST_INTERP 1)
endif()

if(NOT WAMR_BUILD_MULTI_MODULE)
  set(WAMR_BUILD_MULTI_MODULE 0)
endif()

if(NOT WAMR_BUILD_LIB_PTHREAD)
  set(WAMR_BUILD_LIB_PTHREAD 0)
endif()

if(NOT WAMR_BUILD_MINI_LOADER)
  set(WAMR_BUILD_MINI_LOADER 0)
endif()

set(WAMR_BUILD_SIMD 1)
set(WAMR_BUILD_REF_TYPES 1)
set(WAMR_BUILD_GC 1)

include(${REPO_ROOT_DIR}/build-scripts/runtime_lib.cmake)
include(${REPO_ROOT_DIR}/core/shared/utils/uncommon/shared_uncommon.cmake)

add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})
target_include_directories(vmlib PUBLIC ${RUNTIME_LIB_HEADER_LIST})
target_link_directories(vmlib PUBLIC ${RUNTIME_LIB_LINK_LIST})
target_link_libraries(vmlib PUBLIC ${REQUIRED_LLVM_LIBS})

add_executable(wasm_mutator_fuzz wasm_mutator_fuzz.cc)
target_link_libraries(wasm_mutator_fuzz PRIVATE vmlib m)

if(NOT IN_OSS_FUZZ)
  message(STATUS "Enable ASan and UBSan in non-oss-fuzz environment for vmlib")
  target_compile_options(vmlib PUBLIC
    -fprofile-instr-generate -fcoverage-mapping
    -fno-sanitize-recover=all
    -fsanitize=address,undefined
    -fsanitize=float-divide-by-zero,unsigned-integer-overflow,local-bounds,nullability
    -fno-sanitize=alignment
  )
  target_link_options(vmlib PUBLIC -fsanitize=address,undefined -fprofile-instr-generate)
endif()
