/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#ifndef WASI_THREAD_START_H
#define WASI_THREAD_START_H

#define STACK_SIZE 32 * 1024 // same as the main stack

/* See https://github.com/WebAssembly/wasi-threads#design-choice-thread-ids */
#define ASSERT_VALID_TID(TID) \
    (void)TID;                \
    assert(TID >= 1 && TID <= 0x1FFFFFFF && "Invalid thread ID")

typedef struct {
    void *stack;
} start_args_t;

static inline int
start_args_init(start_args_t *start_args)
{
    start_args->stack = malloc(STACK_SIZE);
    if (!start_args->stack) {
        return 0;
    }

    start_args->stack += STACK_SIZE;
    return 1;
}

static inline void
start_args_deinit(start_args_t *start_args)
{
    free(start_args->stack - STACK_SIZE);
}

#endif