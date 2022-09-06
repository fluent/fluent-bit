# Copyright (C) 2021 Intel Corporation and others.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Set WAMR's build options
if("${IDF_TARGET}" STREQUAL "esp32c3")
    set(WAMR_BUILD_TARGET "RISCV32")
else()
    set(WAMR_BUILD_TARGET "XTENSA")
endif()

set(WAMR_BUILD_PLATFORM "esp-idf")

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
  set (WAMR_BUILD_FAST_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_AOT)
  set (WAMR_BUILD_AOT 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_APP_FRAMEWORK)
  set (WAMR_BUILD_APP_FRAMEWORK 0)
endif ()

if (NOT CMAKE_BUILD_EARLY_EXPANSION)
    if (WAMR_BUILD_TARGET STREQUAL "XTENSA")
      idf_build_set_property(COMPILE_DEFINITIONS "-DBUILD_TARGET_XTENSA=1" APPEND)
    endif ()
    if (WAMR_BUILD_INTERP)
      idf_build_set_property(COMPILE_DEFINITIONS "-DWASM_ENABLE_INTERP=1" APPEND)
    endif ()
    if (WAMR_BUILD_AOT)
      idf_build_set_property(COMPILE_DEFINITIONS "-DWASM_ENABLE_AOT=1" APPEND)
    endif ()

    set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)
    include(${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
endif()

idf_component_register(SRCS ${WAMR_RUNTIME_LIB_SOURCE} ${PLATFORM_SHARED_SOURCE}
  INCLUDE_DIRS ${IWASM_DIR}/include ${UTILS_SHARED_DIR} ${PLATFORM_SHARED_DIR} ${PLATFORM_SHARED_DIR}/../include
  REQUIRES pthread
)


