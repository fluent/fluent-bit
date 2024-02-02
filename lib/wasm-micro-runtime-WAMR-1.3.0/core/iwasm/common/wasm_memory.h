/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_MEMORY_H
#define _WASM_MEMORY_H

#include "bh_common.h"
#include "../include/wasm_export.h"
#include "../interpreter/wasm_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
#define GET_LINEAR_MEMORY_SIZE(memory) \
    BH_ATOMIC_32_LOAD(memory->memory_data_size)
#define SET_LINEAR_MEMORY_SIZE(memory, size) \
    BH_ATOMIC_32_STORE(memory->memory_data_size, size)
#else
#define GET_LINEAR_MEMORY_SIZE(memory) memory->memory_data_size
#define SET_LINEAR_MEMORY_SIZE(memory, size) memory->memory_data_size = size
#endif

bool
wasm_runtime_memory_init(mem_alloc_type_t mem_alloc_type,
                         const MemAllocOption *alloc_option);

void
wasm_runtime_memory_destroy();

unsigned
wasm_runtime_memory_pool_size();

void
wasm_runtime_set_mem_bound_check_bytes(WASMMemoryInstance *memory,
                                       uint64 memory_data_size);

void
wasm_runtime_set_enlarge_mem_error_callback(
    const enlarge_memory_error_callback_t callback, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_MEMORY_H */
