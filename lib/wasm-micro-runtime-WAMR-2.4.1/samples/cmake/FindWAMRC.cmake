# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(FindPackageHandleStandardArgs)

find_path(WAMRC_HOME
  wamr-compiler
  PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../..
  NO_DEFAULT_PATH
  NO_CMAKE_PATH
  NO_CMAKE_SYSTEM_PATH
  NO_CMAKE_FIND_ROOT_PATH
  REQUIRED
)

find_file(WAMRC_BIN
  wamrc
  HINTS ${WAMRC_HOME}/wamr-compiler/build
  NO_DEFAULT_PATH
  NO_CMAKE_PATH
  NO_CMAKE_SYSTEM_PATH
  NO_CMAKE_FIND_ROOT_PATH
  REQUIRED
)

find_package_handle_standard_args(WAMRC REQUIRED_VARS WAMRC_BIN)
mark_as_advanced(WAMRC_BIN)
