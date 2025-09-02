# Copyright (C) 2025 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Set default build options with the ability to override from the command line
if(NOT WAMR_BUILD_INTERP)
  set(WAMR_BUILD_INTERP 1)
endif()

set(WAMR_BUILD_WAMR_COMPILER 1)
set(WAMR_BUILD_AOT 0)
set(WAMR_BUILD_INTERP 1)
set(WAMR_BUILD_JIT 0)

include(${SHARED_DIR}/platform/${WAMR_BUILD_PLATFORM}/shared_platform.cmake)
include(${SHARED_DIR}/mem-alloc/mem_alloc.cmake)
include(${SHARED_DIR}/utils/shared_utils.cmake)
include(${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)
include(${IWASM_DIR}/compilation/iwasm_compl.cmake)
include(${IWASM_DIR}/libraries/thread-mgr/thread_mgr.cmake)
include(${IWASM_DIR}/common/iwasm_common.cmake)
include(${IWASM_DIR}/common/gc/iwasm_gc.cmake)
include(${IWASM_DIR}/interpreter/iwasm_interp.cmake)
include(${IWASM_DIR}/aot/iwasm_aot.cmake)
include(${IWASM_DIR}/compilation/iwasm_compl.cmake)
include(${REPO_ROOT_DIR}/build-scripts/version.cmake)

add_library(aotclib
  ${PLATFORM_SHARED_SOURCE}
  ${MEM_ALLOC_SHARED_SOURCE}
  ${UTILS_SHARED_SOURCE}
  ${UNCOMMON_SHARED_SOURCE}
  ${THREAD_MGR_SOURCE}
  ${IWASM_COMMON_SOURCE}
  ${IWASM_INTERP_SOURCE}
  ${IWASM_AOT_SOURCE}
  ${IWASM_GC_SOURCE}
  ${IWASM_COMPL_SOURCE}
)

target_compile_definitions(aotclib
  PUBLIC
    -DWASM_ENABLE_WAMR_COMPILER=1
    -DWASM_ENABLE_FAST_INTERP=0
    -DWASM_ENABLE_INTERP=1
    -DWASM_ENABLE_BULK_MEMORY=1
    -DWASM_ENABLE_SHARED_MEMORY=1
    -DWASM_ENABLE_TAIL_CALL=1
    -DWASM_ENABLE_SIMD=1
    -DWASM_ENABLE_REF_TYPES=1
    -DWASM_ENABLE_MEMORY64=1
    -DWASM_ENABLE_GC=1
    -DWASM_ENABLE_CUSTOM_NAME_SECTION=1
    -DWASM_ENABLE_AOT_STACK_FRAME=1
    -DWASM_ENABLE_DUMP_CALL_STACK=1
    -DWASM_ENABLE_PERF_PROFILING=1
    -DWASM_ENABLE_LOAD_CUSTOM_SECTION=1
    -DWASM_ENABLE_THREAD_MGR=1
    ${LLVM_DEFINITIONS}
)

target_include_directories(aotclib PUBLIC
  ${IWASM_DIR}/include
  ${SHARED_DIR}/include
)

target_link_directories(aotclib PUBLIC ${LLVM_LIBRARY_DIR})

target_link_libraries(aotclib PUBLIC ${REQUIRED_LLVM_LIBS})

if(NOT IN_OSS_FUZZ)
  message(STATUS "Enable ASan and UBSan in non-oss-fuzz environment for aotclib")
  target_compile_options(aotclib PUBLIC
    -fprofile-instr-generate -fcoverage-mapping
    -fno-sanitize-recover=all
    -fsanitize=address,undefined
    -fsanitize=float-divide-by-zero,unsigned-integer-overflow,local-bounds,nullability
    -fno-sanitize=alignment
  )
  target_link_options(aotclib PUBLIC -fsanitize=address,undefined -fprofile-instr-generate)
endif()

add_executable(aot_compiler_fuzz aot_compiler_fuzz.cc)
target_link_libraries(aot_compiler_fuzz PRIVATE stdc++ aotclib)
