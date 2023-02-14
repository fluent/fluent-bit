/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_SHARED_MEMORY_H
#define _WASM_SHARED_MEMORY_H

#include "bh_common.h"
#if WASM_ENABLE_INTERP != 0
#include "wasm_runtime.h"
#endif
#if WASM_ENABLE_AOT != 0
#include "aot_runtime.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WASMSharedMemNode {
    bh_list_link l;
    /* Lock */
    korp_mutex lock;
    /* The module reference */
    WASMModuleCommon *module;
    /* The memory information */
    WASMMemoryInstanceCommon *memory_inst;

    /* reference count */
    uint32 ref_count;
} WASMSharedMemNode;

bool
wasm_shared_memory_init();

void
wasm_shared_memory_destroy();

WASMSharedMemNode *
wasm_module_get_shared_memory(WASMModuleCommon *module);

int32
shared_memory_inc_reference(WASMModuleCommon *module);

int32
shared_memory_dec_reference(WASMModuleCommon *module);

WASMMemoryInstanceCommon *
shared_memory_get_memory_inst(WASMSharedMemNode *node);

WASMSharedMemNode *
shared_memory_set_memory_inst(WASMModuleCommon *module,
                              WASMMemoryInstanceCommon *memory);

uint32
wasm_runtime_atomic_wait(WASMModuleInstanceCommon *module, void *address,
                         uint64 expect, int64 timeout, bool wait64);

uint32
wasm_runtime_atomic_notify(WASMModuleInstanceCommon *module, void *address,
                           uint32 count);

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_SHARED_MEMORY_H */
