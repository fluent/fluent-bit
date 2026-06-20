# Copyright (C) 2023 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Find libuv library
# This module defines
#  LIBUV_FOUND, if false, do not try to link to libuv
#  LIBUV_LIBRARIES
#  LIBUV_INCLUDE_DIR, where to find uv.h

find_path(LIBUV_INCLUDE_DIR NAMES uv.h)
find_library(LIBUV_LIBRARIES NAMES uv libuv)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  LIBUV
  FOUND_VAR LIBUV_FOUND
  REQUIRED_VARS
    LIBUV_LIBRARIES
    LIBUV_INCLUDE_DIR
)

if(WIN32)
  list(APPEND LIBUV_LIBRARIES iphlpapi)
  list(APPEND LIBUV_LIBRARIES psapi)
  list(APPEND LIBUV_LIBRARIES userenv)
  list(APPEND LIBUV_LIBRARIES ws2_32)
endif()
