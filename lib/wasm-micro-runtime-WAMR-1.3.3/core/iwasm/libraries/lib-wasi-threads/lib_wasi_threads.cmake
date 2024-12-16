# Copyright (C) 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (LIB_WASI_THREADS_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_LIB_WASI_THREADS=1 -DWASM_ENABLE_HEAP_AUX_STACK_ALLOCATION=1)

include_directories(${LIB_WASI_THREADS_DIR})

set (LIB_WASI_THREADS_SOURCE
    ${LIB_WASI_THREADS_DIR}/lib_wasi_threads_wrapper.c
    ${LIB_WASI_THREADS_DIR}/tid_allocator.c)