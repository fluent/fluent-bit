# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (APP_MGR_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${APP_MGR_SHARED_DIR})


file (GLOB_RECURSE source_all ${APP_MGR_SHARED_DIR}/*.c)

set (APP_MGR_SHARED_SOURCE ${source_all})

file (GLOB header
    ${APP_MGR_SHARED_DIR}/*.h
)
LIST (APPEND RUNTIME_LIB_HEADER_LIST ${header})
