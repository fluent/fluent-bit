# Copyright (C) 2021 Ant Group.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (DEBUG_ENGINE_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_DEBUG_INTERP=1)

include_directories(${DEBUG_ENGINE_DIR})

file (GLOB source_all ${DEBUG_ENGINE_DIR}/*.c)

set (DEBUG_ENGINE_SOURCE ${source_all})
