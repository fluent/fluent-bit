# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (WASI_NN_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_WASI_NN=1)

set (LIBC_WASI_NN_SOURCE ${WASI_NN_DIR}/wasi_nn_native.c ${WASI_NN_DIR}/wasi_nn_tensorflow.cpp)

set (TENSORFLOW_LIB tensorflow-lite)
