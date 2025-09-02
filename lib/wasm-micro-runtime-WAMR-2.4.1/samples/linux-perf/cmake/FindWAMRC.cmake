# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

include(FindPackageHandleStandardArgs)

find_file(WAMRC_BIN
  NAMES wamrc
  DOC "search wamrc"
  HINTS ${CMAKE_CURRENT_SOURCE_DIR}/../../../wamr-compiler/build
  REQUIRED
)

find_package_handle_standard_args(WAMRC REQUIRED_VARS WAMRC_BIN)
mark_as_advanced(WAMRC_BIN)