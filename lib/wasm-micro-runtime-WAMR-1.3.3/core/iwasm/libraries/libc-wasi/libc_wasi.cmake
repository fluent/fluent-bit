# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (LIBC_WASI_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_LIBC_WASI=1)

include_directories(${LIBC_WASI_DIR}/sandboxed-system-primitives/include
                    ${LIBC_WASI_DIR}/sandboxed-system-primitives/src)

file (GLOB_RECURSE source_all ${LIBC_WASI_DIR}/*.c )

set (LIBC_WASI_SOURCE ${source_all})
