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

set (IWASM_AOT_SOURCE ${c_source_all} ${arch_source} ${debug_source})

