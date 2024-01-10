# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (LIB_COAP_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${LIB_COAP_DIR}/er-coap)
include_directories(${LIB_COAP_DIR}/extension)

file (GLOB_RECURSE source_all ${LIB_COAP_DIR}/*.c)

set (LIB_COAP_SOURCE ${source_all})

