# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#######################################
include(ExternalProject)

file(REAL_PATH ../../.. WAMR_ROOT
  BASE_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
)

find_path(WASI_SDK_PARENT
  name wasi-sdk
  PATHS ${WAMR_ROOT}/test-tools/
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH
)

if(NOT WASI_SDK_PARENT)
  message(FATAL_ERROR
    "can not find 'wasi-sdk' under ${WAMR_ROOT}/test-tools, "
    "please run ${WAMR_ROOT}/test-tools/build-wasi-sdk/build_wasi_sdk.py "
    "to build wasi-sdk and try again"
  )
endif()

set(WASI_SDK_HOME ${WASI_SDK_PARENT}/wasi-sdk)
message(CHECK_START "Detecting WASI-SDK at ${WASI_SDK_HOME}")
if(EXISTS "${WASI_SDK_HOME}/share/cmake/wasi-sdk.cmake")
  message(CHECK_PASS "found")
else()
  message(CHECK_FAIL "not found")
endif()

################  BINARYEN ################
find_program(WASM_OPT
  NAMES wasm-opt
  PATHS /opt/binaryen-version_101/bin /opt/binaryen/bin
  NO_DEFAULT_PATH
  NO_CMAKE_FIND_ROOT_PATH
)

if(NOT WASM_OPT)
  message(FATAL_ERROR
    "can not find wasm-opt. "
    "please download it from "
    "https://github.com/WebAssembly/binaryen/releases/download/version_101/binaryen-version_101-x86_64-linux.tar.gz "
    "and install it under /opt"
  )
endif()
