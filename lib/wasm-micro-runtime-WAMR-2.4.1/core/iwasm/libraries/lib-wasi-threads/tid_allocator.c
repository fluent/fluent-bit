/*
 * Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "tid_allocator.h"
#include "wasm_export.h"
#include "bh_log.h"

bh_static_assert(TID_MIN <= TID_MAX);
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

bool
tid_allocator_init(TidAllocator *tid_allocator)
{
    tid_allocator->size = MIN(TID_ALLOCATOR_INIT_SIZE, TID_MAX - TID_MIN + 1);
    tid_allocator->pos = tid_allocator->size;
    tid_allocator->ids =
        wasm_runtime_malloc(tid_allocator->size * sizeof(int32));
    if (tid_allocator->ids == NULL)
        return false;

    for (int64 i = tid_allocator->pos - 1; i >= 0; i--)
        tid_allocator->ids[i] =
            (uint32)(TID_MIN + (tid_allocator->pos - 1 - i));

    return true;
}

void
tid_allocator_deinit(TidAllocator *tid_allocator)
{
    wasm_runtime_free(tid_allocator->ids);
}

int32
tid_allocator_get_tid(TidAllocator *tid_allocator)
{
    if (tid_allocator->pos == 0) { // Resize stack and push new thread ids
        if (tid_allocator->size == TID_MAX - TID_MIN + 1) {
            LOG_ERROR("Maximum thread identifier reached");
            return -1;
        }

        uint32 old_size = tid_allocator->size;
        uint32 new_size = MIN(tid_allocator->size * 2, TID_MAX - TID_MIN + 1);
        if (new_size != TID_MAX - TID_MIN + 1
            && new_size / 2 != tid_allocator->size) {
            LOG_ERROR("Overflow detected during new size calculation");
            return -1;
        }

        size_t realloc_size = new_size * sizeof(int32);
        if (realloc_size / sizeof(int32) != new_size) {
            LOG_ERROR("Overflow detected during realloc");
            return -1;
        }
        int32 *tmp =
            wasm_runtime_realloc(tid_allocator->ids, (uint32)realloc_size);
        if (tmp == NULL) {
            LOG_ERROR("Thread ID allocator realloc failed");
            return -1;
        }

        tid_allocator->size = new_size;
        tid_allocator->pos = new_size - old_size;
        tid_allocator->ids = tmp;
        for (int64 i = tid_allocator->pos - 1; i >= 0; i--)
            tid_allocator->ids[i] =
                (uint32)(TID_MIN + (tid_allocator->size - 1 - i));
    }

    // Pop available thread identifier from the stack
    return tid_allocator->ids[--tid_allocator->pos];
}

void
tid_allocator_release_tid(TidAllocator *tid_allocator, int32 thread_id)
{
    // Release thread identifier by pushing it into the stack
    bh_assert(tid_allocator->pos < tid_allocator->size);
    tid_allocator->ids[tid_allocator->pos++] = thread_id;
}
