# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (IWASM_AOT_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_AOT=1)

include_directories (${IWASM_AOT_DIR})

file (GLOB c_source_all ${IWASM_AOT_DIR}/*.c)

if (WAMR_BUILD_TARGET STREQUAL "X86_64" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_x86_64.c)
elseif (WAMR_BUILD_TARGET STREQUAL "X86_32")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_x86_32.c)
elseif (WAMR_BUILD_TARGET MATCHES "AARCH64.*")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_aarch64.c)
elseif (WAMR_BUILD_TARGET MATCHES "ARM.*")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_arm.c)
elseif (WAMR_BUILD_TARGET MATCHES "THUMB.*")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_thumb.c)
elseif (WAMR_BUILD_TARGET STREQUAL "MIPS")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_mips.c)
elseif (WAMR_BUILD_TARGET STREQUAL "XTENSA")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_xtensa.c)
elseif (WAMR_BUILD_TARGET MATCHES "RISCV*")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_riscv.c)
elseif (WAMR_BUILD_TARGET STREQUAL "ARC")
  set (arch_source ${IWASM_AOT_DIR}/arch/aot_reloc_arc.c)
else ()
  message (FATAL_ERROR "Build target isn't set")
endif ()

if (WAMR_BUILD_DEBUG_AOT EQUAL 1)
  add_definitions(-DWASM_ENABLE_DEBUG_AOT=1)
  file(GLOB debug_source ${IWASM_AOT_DIR}/debug/*.c)
endif()

if ((WAMR_BUILD_TARGET STREQUAL "X86_64" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
    AND (WAMR_BUILD_PLATFORM STREQUAL "windows")
    AND (NOT WAMR_DISABLE_HW_BOUND_CHECK EQUAL 1))
  include(FetchContent)

  FetchContent_Declare(
    zycore
    GIT_REPOSITORY https://github.com/zyantific/zycore-c.git
  )
  FetchContent_GetProperties(zycore)
  if (NOT zycore_POPULATED)
    message ("-- Fetching zycore ..")
    FetchContent_Populate(zycore)
    include_directories("${zycore_SOURCE_DIR}/include")
    include_directories("${zycore_BINARY_DIR}")
    add_definitions(-DZYCORE_STATIC_BUILD=1)
    add_subdirectory(${zycore_SOURCE_DIR} ${zycore_BINARY_DIR} EXCLUDE_FROM_ALL)
    file (GLOB_RECURSE c_source_zycore ${zycore_SOURCE_DIR}/src/*.c)
  endif ()

  FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG e14a07895136182a5b53e181eec3b1c6e0b434de
  )
  FetchContent_GetProperties(zydis)
  if (NOT zydis_POPULATED)
    message ("-- Fetching zydis ..")
    FetchContent_Populate(zydis)
    option(ZYDIS_FEATURE_ENCODER "" OFF)
    option(ZYDIS_BUILD_TOOLS "" OFF)
    option(ZYDIS_BUILD_EXAMPLES "" OFF)
    option(ZYDIS_BUILD_MAN "" OFF)
    option(ZYDIS_BUILD_DOXYGEN "" OFF)
    include_directories("${zydis_BINARY_DIR}")
    include_directories("${zydis_SOURCE_DIR}/include")
    include_directories("${zydis_SOURCE_DIR}/src")
    add_definitions(-DZYDIS_STATIC_BUILD=1)
    add_subdirectory(${zydis_SOURCE_DIR} ${zydis_BINARY_DIR} EXCLUDE_FROM_ALL)
    file (GLOB_RECURSE c_source_zydis ${zydis_SOURCE_DIR}/src/*.c)
  endif ()
endif ()


set (IWASM_AOT_SOURCE ${c_source_all} ${arch_source} ${debug_source}
	              ${c_source_zycore} ${c_source_zydis})
