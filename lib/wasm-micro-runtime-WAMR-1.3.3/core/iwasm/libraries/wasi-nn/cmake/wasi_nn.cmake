# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

# Find tensorflow-lite
find_package(tensorflow_lite REQUIRED)

set(WASI_NN_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

include_directories (${WASI_NN_ROOT_DIR}/include)
include_directories (${WASI_NN_ROOT_DIR}/src)
include_directories (${WASI_NN_ROOT_DIR}/src/utils)

set (
  WASI_NN_SOURCES
  ${WASI_NN_ROOT_DIR}/src/wasi_nn.c
  ${WASI_NN_ROOT_DIR}/src/wasi_nn_tensorflowlite.cpp
  ${WASI_NN_ROOT_DIR}/src/utils/wasi_nn_app_native.c
)

set (WASI_NN_LIBS tensorflow-lite)
