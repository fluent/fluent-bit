# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (NATIVE_INTERFACE_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${NATIVE_INTERFACE_DIR})


file (GLOB_RECURSE source_all ${NATIVE_INTERFACE_DIR}/*.c)

set (NATIVE_INTERFACE_SOURCE ${source_all})

set (WASM_APP_BI_INC_DIR "${NATIVE_INTERFACE_DIR}/bi-inc")
LIST (APPEND RUNTIME_LIB_HEADER_LIST "${NATIVE_INTERFACE_DIR}/native_interface.h")

