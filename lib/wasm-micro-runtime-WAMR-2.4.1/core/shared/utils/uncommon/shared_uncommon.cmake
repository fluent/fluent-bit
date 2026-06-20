# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (UNCOMMON_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${UNCOMMON_SHARED_DIR})

file (GLOB_RECURSE source_all ${UNCOMMON_SHARED_DIR}/*.c)

set (UNCOMMON_SHARED_SOURCE ${source_all})

