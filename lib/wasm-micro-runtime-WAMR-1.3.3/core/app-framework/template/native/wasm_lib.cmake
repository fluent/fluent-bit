# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (WASM_LIB_CURRENT_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(
    ${WASM_LIB_CURRENT_DIR}
    # Add your include dir here
)

file (GLOB_RECURSE source_all
    ${WASM_LIB_CURRENT_DIR}/*.c
    # Add your source file here
)

set (WASM_APP_LIB_CURRENT_SOURCE ${source_all})

