# Copyright (C) 2021 Intel Corporation and others.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Set WAMR's build options
if (NOT CMAKE_BUILD_EARLY_EXPANSION)

  if (CONFIG_IDF_TARGET_ARCH_RISCV)
    if (CONFIG_IDF_TARGET_ESP32P4)
      set (WAMR_BUILD_TARGET "RISCV32_ILP32F")
    else ()
      set (WAMR_BUILD_TARGET "RISCV32_ILP32")
    endif ()
  elseif (CONFIG_IDF_TARGET_ARCH_XTENSA)
    set (WAMR_BUILD_TARGET "XTENSA")
  else ()
    message (FATAL_ERROR "Arch ${CONFIG_IDF_TARGET_ARCH} is not supported")
  endif ()

  set (WAMR_BUILD_PLATFORM "esp-idf")

  if (CONFIG_WAMR_BUILD_DEBUG)
    set (CMAKE_BUILD_TYPE Debug)
  else ()
    set (CMAKE_BUILD_TYPE Release)
  endif ()

  if (CONFIG_WAMR_ENABLE_INTERP)
    set (WAMR_BUILD_INTERP 1)
  endif ()

  if (CONFIG_WAMR_INTERP_FAST)
    set (WAMR_BUILD_FAST_INTERP 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_AOT)
    set (WAMR_BUILD_AOT 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_LIBC_BUILTIN)
    set (WAMR_BUILD_LIBC_BUILTIN 1)
  endif ()

  if (CONFIG_WAMR_INTERP_LOADER_MINI)
    set (WAMR_BUILD_MINI_LOADER 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_MULTI_MODULE)
    set (WAMR_BUILD_MULTI_MODULE 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_SHARED_MEMORY)
    set (WAMR_BUILD_SHARED_MEMORY 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_MEMORY_PROFILING)
    set (WAMR_BUILD_MEMORY_PROFILING 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_PERF_PROFILING)
    set (WAMR_BUILD_PERF_PROFILING 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_REF_TYPES)
    set (WAMR_BUILD_REF_TYPES 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_LIBC_WASI)
    set (WAMR_BUILD_LIBC_WASI 1)
  endif ()

  if (CONFIG_WAMR_ENABLE_LIB_PTHREAD)
    set (WAMR_BUILD_LIB_PTHREAD 1)
  endif ()

  set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)
  include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

  list (APPEND srcs "${WAMR_RUNTIME_LIB_SOURCE}"
                    "${PLATFORM_SHARED_SOURCE}")

  set (include_dirs "${IWASM_DIR}/include"
                    "${UTILS_SHARED_DIR}"
                    "${PLATFORM_SHARED_DIR}"
                    "${PLATFORM_SHARED_DIR}/../include"
                    "${IWASM_COMMON_DIR}")
endif ()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ${include_dirs}
                       REQUIRES pthread lwip esp_timer
                       KCONFIG ${CMAKE_CURRENT_LIST_DIR}/Kconfig)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")

if (CONFIG_IDF_TARGET_ARCH_RISCV)
  if (CONFIG_IDF_TARGET_ESP32P4)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC -DBUILD_TARGET_RISCV32_ILP32F=1)
  else ()
    target_compile_definitions(${COMPONENT_LIB} PUBLIC -DBUILD_TARGET_RISCV32_ILP32=1)
  endif ()
elseif (CONFIG_IDF_TARGET_ARCH_XTENSA)
  target_compile_definitions(${COMPONENT_LIB} PUBLIC -DBUILD_TARGET_XTENSA=1)
endif ()

if (CONFIG_WAMR_ENABLE_AOT)
  target_compile_definitions(${COMPONENT_LIB} PUBLIC -DWASM_ENABLE_AOT=1)
endif ()

if (CONFIG_WAMR_ENABLE_INTERP)
  target_compile_definitions(${COMPONENT_LIB} PUBLIC -DWASM_ENABLE_INTERP=1)
endif ()
