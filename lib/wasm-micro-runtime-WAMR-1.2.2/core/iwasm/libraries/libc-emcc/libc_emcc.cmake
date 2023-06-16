# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (LIBC_EMCC_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_LIBC_EMCC=1)

include_directories(${LIBC_EMCC_DIR})

file (GLOB source_all ${LIBC_EMCC_DIR}/*.c)

set (LIBC_EMCC_SOURCE ${source_all})