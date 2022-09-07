# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (LIB_PTHREAD_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_LIB_PTHREAD=1)

include_directories(${LIB_PTHREAD_DIR})

file (GLOB source_all ${LIB_PTHREAD_DIR}/*.c)

set (LIB_PTHREAD_SOURCE ${source_all})

