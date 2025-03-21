# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (WASM_LIB_CONN_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${WASM_LIB_CONN_DIR})

add_definitions (-DAPP_FRAMEWORK_CONNECTION)


include (${CMAKE_CURRENT_LIST_DIR}/${WAMR_BUILD_PLATFORM}/connection_mgr.cmake)

file (GLOB source_all
    ${WASM_LIB_CONN_MGR_SOURCE}
    ${WASM_LIB_CONN_DIR}/*.c
)

set (WASM_APP_LIB_CURRENT_SOURCE ${source_all})
