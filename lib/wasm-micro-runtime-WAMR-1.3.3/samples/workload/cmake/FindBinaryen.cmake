# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# Output below variables:
#   - Binaryen_HOME. the installation location
#

include(CMakePrintHelpers)
include(FindPackageHandleStandardArgs)

file(GLOB Binaryen_SEARCH_PATH "/opt/binaryen*")
find_path(Binaryen_HOME
  NAMES bin/wasm-opt
  PATHS ${Binaryen_SEARCH_PATH}
  NO_CMAKE_FIND_ROOT_PATH
  NO_SYSTEM_ENVIRONMENT_PATH
  REQUIRED
)

execute_process(
  COMMAND ${Binaryen_HOME}/bin/wasm-opt --version
  OUTPUT_VARIABLE WASM_OPT_OUTPUT
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

string(REGEX MATCH version_[0-9]+ Binaryen_VERSION_tmp ${WASM_OPT_OUTPUT})
string(REGEX MATCH [0-9]+ Binaryen_VERSION ${Binaryen_VERSION_tmp})

#cmake_print_variables(Binaryen_VERSION_tmp Binaryen_VERSION)

find_package_handle_standard_args(Binaryen REQUIRED_VARS Binaryen_HOME VERSION_VAR Binaryen_VERSION)

if(Binaryen_FOUND)
  mark_as_advanced(Binaryen_SEARCH_PATH)
  mark_as_advanced(Binaryen_VERSION_tmp)
  mark_as_advanced(Binaryen_VERSION)
  mark_as_advanced(WASM_OPT_OUTPUT)

  set(Binaryen_WASM_OPT ${Binaryen_HOME}/bin/wasm-opt)
else()
  # TODO: install WASISDK
endif()
