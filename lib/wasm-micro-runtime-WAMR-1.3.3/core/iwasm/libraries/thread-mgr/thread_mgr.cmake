# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (THREAD_MGR_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_THREAD_MGR=1)

include_directories(${THREAD_MGR_DIR})

file (GLOB source_all ${THREAD_MGR_DIR}/*.c)

set (THREAD_MGR_SOURCE ${source_all})

