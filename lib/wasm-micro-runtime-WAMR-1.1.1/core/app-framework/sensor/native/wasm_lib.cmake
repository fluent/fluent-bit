# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (WASM_LIB_SENSOR_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DAPP_FRAMEWORK_SENSOR)

include_directories(${WASM_LIB_SENSOR_DIR})


file (GLOB_RECURSE source_all ${WASM_LIB_SENSOR_DIR}/*.c)

set (WASM_APP_LIB_CURRENT_SOURCE ${source_all})

