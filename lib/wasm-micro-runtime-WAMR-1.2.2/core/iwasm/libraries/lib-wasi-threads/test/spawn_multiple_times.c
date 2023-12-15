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
    NUM_ITER = 50,
    NUM_RETRY = 5,
    SECOND = 1000 * 1000 * 1000, /* 1 second */
    TIMEOUT = 5LL * SECOND
};

typedef struct {
    start_args_t base;
    int th_done;
} shared_t;

int g_count = 0;

void
__wasi_thread_start_C(int thread_id, int *start_arg)
{
    shared_t *data = (shared_t *)start_arg;

    g_count++;

    __atomic_store_n(&data->th_done, 1, __ATOMIC_SEQ_CST);
    __builtin_wasm_memory_atomic_notify(&data->th_done, 1);
}

int
main(int argc, char **argv)
{
    shared_t data = { 0 };
    assert(start_args_init(&data.base) && "Stack allocation for thread failed");

    for (int i = 0; i < NUM_ITER; i++) {
        data.th_done = 0;

        printf("Creating thread\n");
        int thread_id = -1;
        for (int j = 0; j < NUM_RETRY && thread_id < 0; j++) {
            thread_id = __wasi_thread_spawn(&data);
            if (thread_id < 0)
                __builtin_wasm_memory_atomic_wait32(NULL, 0, SECOND);
        }
        assert(thread_id > 0 && "Thread creation should succeed");

        printf("Waiting for thread to finish\n");
        if (__builtin_wasm_memory_atomic_wait32(&data.th_done, 0, TIMEOUT)
            == 2) {
            assert(false && "Wait should not time out");
        }
        printf("Thread has finished\n");
    }

    assert(g_count == NUM_ITER && "Count has not been updated correctly");

    start_args_deinit(&data.base);
    return EXIT_SUCCESS;
}
