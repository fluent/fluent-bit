# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if(NOT WAMR_ROOT_DIR)
  # if from wamr-compiler
  set(WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
endif()

set(WAMR_VERSION_MAJOR 2)
set(WAMR_VERSION_MINOR 4)
set(WAMR_VERSION_PATCH 1)

message("-- WAMR version: ${WAMR_VERSION_MAJOR}.${WAMR_VERSION_MINOR}.${WAMR_VERSION_PATCH}")

# Configure the version header file
configure_file(
  ${WAMR_ROOT_DIR}/core/version.h.in
  ${WAMR_ROOT_DIR}/core/version.h
)

# Set the library version and SOVERSION
function(set_version_info target)
  set_target_properties(${target}
    PROPERTIES
      VERSION ${WAMR_VERSION_MAJOR}.${WAMR_VERSION_MINOR}.${WAMR_VERSION_PATCH}
      SOVERSION ${WAMR_VERSION_MAJOR}
)
endfunction()
