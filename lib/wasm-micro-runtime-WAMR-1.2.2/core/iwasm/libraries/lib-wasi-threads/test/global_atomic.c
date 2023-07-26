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
#include <stdbool.h>

#include "wasi_thread_start.h"

enum CONSTANTS {
    NUM_THREADS = 4,
    NUM_ITER = 1000,
    SECOND = 1000 * 1000 * 1000, /* 1 second */
    TIMEOUT = 10LL * SECOND
};

int g_count = 0;

typedef struct {
    start_args_t base;
    int th_done;
} shared_t;

void
__wasi_thread_start_C(int thread_id, int *start_arg)
{
    shared_t *data = (shared_t *)start_arg;

    for (int i = 0; i < NUM_ITER; i++)
        __atomic_fetch_add(&g_count, 1, __ATOMIC_SEQ_CST);

    __atomic_store_n(&data->th_done, 1, __ATOMIC_SEQ_CST);
    __builtin_wasm_memory_atomic_notify(&data->th_done, 1);
}

int
main(int argc, char **argv)
{
    shared_t data[NUM_THREADS] = { 0 };
    int thread_ids[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        assert(start_args_init(&data[i].base));
        thread_ids[i] = __wasi_thread_spawn(&data[i]);
        assert(thread_ids[i] > 0 && "Thread creation failed");
    }

    printf("Wait for threads to finish\n");
    for (int i = 0; i < NUM_THREADS; i++) {
        if (__builtin_wasm_memory_atomic_wait32(&data[i].th_done, 0, TIMEOUT)
            == 2) {
            assert(false && "Wait should not time out");
        }

        start_args_deinit(&data[i].base);
    }

    printf("Value of count after update: %d\n", g_count);
    assert(g_count == (NUM_THREADS * NUM_ITER)
           && "Global count not updated correctly");

    return EXIT_SUCCESS;
}
