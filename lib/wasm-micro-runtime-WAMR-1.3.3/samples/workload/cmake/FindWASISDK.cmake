# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# Output below variables:
#   - WASISDK_HOME. the installation location
#   - WASISDK_SYSROOT. where wasi-sysroot is
#   - WASISDK_TOOLCHAIN. where wasi-sdk.cmake is
#

include(CMakePrintHelpers)
include(FindPackageHandleStandardArgs)

file(GLOB WASISDK_SEARCH_PATH "/opt/wasi-sdk-*")
find_path(WASISDK_HOME
  NAMES share/wasi-sysroot
  PATHS ${WASISDK_SEARCH_PATH}
  NO_CMAKE_FIND_ROOT_PATH
  NO_SYSTEM_ENVIRONMENT_PATH
  REQUIRED
)

string(REGEX MATCH [0-9]+\.[0-9]+\.*[0-9]* WASISDK_VERSION ${WASISDK_HOME})

#cmake_print_variables(WASISDK_HOME WASISDK_VERSION)
find_package_handle_standard_args(WASISDK REQUIRED_VARS WASISDK_HOME VERSION_VAR WASISDK_VERSION)

if(WASISDK_FOUND)
  mark_as_advanced(WASISDK_SEARCH_PATH)
  mark_as_advanced(WASISDK_VERSION)

  set(WASISDK_CC_COMMAND     ${WASISDK_HOME}/bin/clang)
  set(WASISDK_CXX_COMMAND    ${WASISDK_HOME}/bin/clang++)
  set(WASISDK_SYSROOT        ${WASISDK_HOME}/share/wasi-sysroot)
  set(WASISDK_TOOLCHAIN      ${WASISDK_HOME}/share/cmake/wasi-sdk.cmake)
else()
  # TODO: install WASISDK
endif()
