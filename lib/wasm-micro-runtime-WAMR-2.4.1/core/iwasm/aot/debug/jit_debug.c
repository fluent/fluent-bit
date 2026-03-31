/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_log.h"
#include "bh_platform.h"
#include "../../interpreter/wasm_runtime.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

/* This must be kept in sync with gdb/gdb/jit.h */
#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */
typedef enum JITAction {
    JIT_NOACTION = 0,
    JIT_REGISTER_FN,
    JIT_UNREGISTER_FN
} JITAction;
/* clang-format on */

typedef struct JITCodeEntry {
    struct JITCodeEntry *next_;
    struct JITCodeEntry *prev_;
    const uint8 *symfile_addr_;
    uint64 symfile_size_;
} JITCodeEntry;

typedef struct JITDescriptor {
    uint32 version_;
    uint32 action_flag_;
    JITCodeEntry *relevant_entry_;
    JITCodeEntry *first_entry_;
} JITDescriptor;

#if defined(_WIN32) || defined(_WIN32_)
#define attribute_noinline __declspec(noinline)
#else
#define attribute_noinline __attribute__((noinline))
#endif

/* LLVM has already define this */
#if (WASM_ENABLE_WAMR_COMPILER == 0) && (WASM_ENABLE_JIT == 0)
/**
 * GDB will place breakpoint into this function.
 * To prevent GCC from inlining or removing it we place noinline attribute
 * and inline assembler statement inside.
 */
void attribute_noinline
__jit_debug_register_code(void);

void attribute_noinline
__jit_debug_register_code(void)
{
    int x;
    *(char *)&x = '\0';
}

/**
 * GDB will inspect contents of this descriptor.
 * Static initialization is necessary to prevent GDB from seeing
 * uninitialized descriptor.
 */

JITDescriptor __jit_debug_descriptor = { 1, JIT_NOACTION, NULL, NULL };
#else
extern void
__jit_debug_register_code();
extern JITDescriptor __jit_debug_descriptor;
#endif

/**
 * Call __jit_debug_register_code indirectly via global variable.
 * This gives the debugger an easy way to inject custom code to
 * handle the events.
 */
void (*__jit_debug_register_code_ptr)(void) = __jit_debug_register_code;

#ifdef __cplusplus
}
#endif

typedef struct WASMJITDebugEngine {
    korp_mutex jit_entry_lock;
    bh_list jit_entry_list;
} WASMJITDebugEngine;

typedef struct WASMJITEntryNode {
    struct WASMJITEntryNode *next;
    JITCodeEntry *entry;
} WASMJITEntryNode;

static WASMJITDebugEngine *jit_debug_engine;

static JITCodeEntry *
CreateJITCodeEntryInternal(const uint8 *symfile_addr, uint64 symfile_size)
{
    JITCodeEntry *entry;

    os_mutex_lock(&jit_debug_engine->jit_entry_lock);

    if (!(entry = wasm_runtime_malloc(sizeof(JITCodeEntry)))) {
        LOG_ERROR("WASM JIT Debug Engine error: failed to allocate memory");
        os_mutex_unlock(&jit_debug_engine->jit_entry_lock);
        return NULL;
    }
    entry->symfile_addr_ = symfile_addr;
    entry->symfile_size_ = symfile_size;
    entry->prev_ = NULL;

    entry->next_ = __jit_debug_descriptor.first_entry_;
    if (entry->next_ != NULL) {
        entry->next_->prev_ = entry;
    }
    __jit_debug_descriptor.first_entry_ = entry;
    __jit_debug_descriptor.relevant_entry_ = entry;

    __jit_debug_descriptor.action_flag_ = JIT_REGISTER_FN;

    (*__jit_debug_register_code_ptr)();

    os_mutex_unlock(&jit_debug_engine->jit_entry_lock);
    return entry;
}

static void
DestroyJITCodeEntryInternal(JITCodeEntry *entry)
{
    os_mutex_lock(&jit_debug_engine->jit_entry_lock);

    if (entry->prev_ != NULL) {
        entry->prev_->next_ = entry->next_;
    }
    else {
        __jit_debug_descriptor.first_entry_ = entry->next_;
    }

    if (entry->next_ != NULL) {
        entry->next_->prev_ = entry->prev_;
    }

    __jit_debug_descriptor.relevant_entry_ = entry;
    __jit_debug_descriptor.action_flag_ = JIT_UNREGISTER_FN;
    (*__jit_debug_register_code_ptr)();

    wasm_runtime_free(entry);

    os_mutex_unlock(&jit_debug_engine->jit_entry_lock);
}

bool
jit_debug_engine_init(void)
{
    if (jit_debug_engine) {
        return true;
    }

    if (!(jit_debug_engine = wasm_runtime_malloc(sizeof(WASMJITDebugEngine)))) {
        LOG_ERROR("WASM JIT Debug Engine error: failed to allocate memory");
        return false;
    }
    memset(jit_debug_engine, 0, sizeof(WASMJITDebugEngine));

    if (os_mutex_init(&jit_debug_engine->jit_entry_lock) != 0) {
        wasm_runtime_free(jit_debug_engine);
        jit_debug_engine = NULL;
        return false;
    }

    bh_list_init(&jit_debug_engine->jit_entry_list);
    return true;
}

void
jit_debug_engine_destroy(void)
{
    if (jit_debug_engine) {
        WASMJITEntryNode *node, *node_next;

        /* Destroy all nodes */
        node = bh_list_first_elem(&jit_debug_engine->jit_entry_list);
        while (node) {
            node_next = bh_list_elem_next(node);
            DestroyJITCodeEntryInternal(node->entry);
            bh_list_remove(&jit_debug_engine->jit_entry_list, node);
            wasm_runtime_free(node);
            node = node_next;
        }

        /* Destroy JIT Debug Engine */
        os_mutex_destroy(&jit_debug_engine->jit_entry_lock);
        wasm_runtime_free(jit_debug_engine);
        jit_debug_engine = NULL;
    }
}

bool
jit_code_entry_create(const uint8 *symfile_addr, uint64 symfile_size)
{
    JITCodeEntry *entry;
    WASMJITEntryNode *node;

    if (!(node = wasm_runtime_malloc(sizeof(WASMJITEntryNode)))) {
        LOG_ERROR("WASM JIT Debug Engine error: failed to allocate memory");
        return false;
    }

    entry = CreateJITCodeEntryInternal(symfile_addr, symfile_size);

    if (!entry) {
        wasm_runtime_free(node);
        return false;
    }

    node->entry = entry;
    os_mutex_lock(&jit_debug_engine->jit_entry_lock);
    bh_list_insert(&jit_debug_engine->jit_entry_list, node);
    os_mutex_unlock(&jit_debug_engine->jit_entry_lock);
    return true;
}

void
jit_code_entry_destroy(const uint8 *symfile_addr)
{
    WASMJITEntryNode *node;

    node = bh_list_first_elem(&jit_debug_engine->jit_entry_list);
    while (node) {
        WASMJITEntryNode *next_node = bh_list_elem_next(node);
        if (node->entry->symfile_addr_ == symfile_addr) {
            DestroyJITCodeEntryInternal(node->entry);
            os_mutex_lock(&jit_debug_engine->jit_entry_lock);
            bh_list_remove(&jit_debug_engine->jit_entry_list, node);
            os_mutex_unlock(&jit_debug_engine->jit_entry_lock);
            wasm_runtime_free(node);
        }
        node = next_node;
    }
}
