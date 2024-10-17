# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (__APP_MGR_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${__APP_MGR_DIR})


file (GLOB source_all ${__APP_MGR_DIR}/*.c  ${__APP_MGR_DIR}/platform/${WAMR_BUILD_PLATFORM}/*.c)

set (APP_MGR_SOURCE ${source_all})

file (GLOB header
    ${__APP_MGR_DIR}/module_wasm_app.h
)
LIST (APPEND RUNTIME_LIB_HEADER_LIST ${header})

