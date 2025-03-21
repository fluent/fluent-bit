# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (WASM_APP_BASE_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${WASM_APP_BASE_DIR})

add_definitions (-DWASM_ENABLE_BASE_LIB)

file (GLOB_RECURSE source_all ${WASM_APP_BASE_DIR}/*.c)

set (WASM_APP_CURRENT_SOURCE ${source_all})
set (WASM_APP_BASE_DIR ${WASM_APP_BASE_DIR} PARENT_SCOPE)
