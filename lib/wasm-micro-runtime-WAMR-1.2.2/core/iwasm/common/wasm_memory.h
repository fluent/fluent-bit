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

bool
wasm_runtime_memory_init(mem_alloc_type_t mem_alloc_type,
                         const MemAllocOption *alloc_option);

void
wasm_runtime_memory_destroy();

unsigned
wasm_runtime_memory_pool_size();

#if !defined(OS_ENABLE_HW_BOUND_CHECK)              \
    || WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0 \
    || WASM_ENABLE_BULK_MEMORY != 0
uint32
wasm_get_num_bytes_per_page(WASMMemoryInstance *memory, void *node);

uint32
wasm_get_linear_memory_size(WASMMemoryInstance *memory, void *node);
#endif

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_MEMORY_H */
