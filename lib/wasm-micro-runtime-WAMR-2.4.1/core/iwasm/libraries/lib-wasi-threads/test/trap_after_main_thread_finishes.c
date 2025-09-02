/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef __wasi__
#error This example only compiles to WASM/WASI target
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "wasi_thread_start.h"

enum CONSTANTS {
    SECOND = 1000 * 1000 * 1000, /* 1 second */
    TIMEOUT = 1LL * SECOND
};

typedef struct {
    start_args_t base;
} shared_t;

void
__wasi_thread_start_C(int thread_id, int *start_arg)
{
    /* Wait so that the exception is raised after the main thread has finished
     * already */
    __builtin_wasm_memory_atomic_wait32(NULL, 0, TIMEOUT);
    __builtin_trap();
}

int
main(int argc, char **argv)
{
    shared_t data = { 0 };

    assert(start_args_init(&data.base));
    int thread_id = __wasi_thread_spawn(&data);
    ASSERT_VALID_TID(thread_id);

    return EXIT_SUCCESS;
}
