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
    MAX_NUM_THREADS = 4, /* Should be the same as "--max-threads" */
    NUM_RETRY = 5,
    SECOND = 1000 * 1000 * 1000, /* 1 second */
    TIMEOUT = 10LL * SECOND
};

int g_count = 0;

typedef struct {
    start_args_t base;
    int th_ready;
    int th_continue;
    int th_done;
    bool no_ops;
} shared_t;

void
__wasi_thread_start_C(int thread_id, int *start_arg)
{
    shared_t *data = (shared_t *)start_arg;

    if (data->no_ops) {
        __builtin_wasm_memory_atomic_wait32(NULL, 0, 2 * SECOND);
        return;
    }

    __atomic_store_n(&data->th_ready, 1, __ATOMIC_SEQ_CST);
    __builtin_wasm_memory_atomic_notify(&data->th_ready, 1);

    if (__builtin_wasm_memory_atomic_wait32(&data->th_continue, 0, TIMEOUT)
        == 2) {
        assert(false && "Wait should not time out");
    }

    __atomic_fetch_add(&g_count, 1, __ATOMIC_SEQ_CST);

    __atomic_store_n(&data->th_done, 1, __ATOMIC_SEQ_CST);
    __builtin_wasm_memory_atomic_notify(&data->th_done, 1);
}

int
main(int argc, char **argv)
{
    shared_t data[MAX_NUM_THREADS] = { 0 };
    int thread_ids[MAX_NUM_THREADS];

    for (int i = 0; i < MAX_NUM_THREADS; i++) {
        assert(start_args_init(&data[i].base));
        thread_ids[i] = __wasi_thread_spawn(&data[i]);
        printf("Thread created with id=%d\n", thread_ids[i]);
        ASSERT_VALID_TID(thread_ids[i]);

        for (int j = 0; j < i; j++) {
            assert(thread_ids[i] != thread_ids[j] && "Duplicated TIDs");
        }

        if (__builtin_wasm_memory_atomic_wait32(&data[i].th_ready, 0, TIMEOUT)
            == 2) {
            assert(false && "Wait should not time out");
        }
    }

    printf("Attempt to create thread when not possible\n");
    shared_t data_fail = { 0 };
    assert(start_args_init(&data_fail.base));
    int thread_id = __wasi_thread_spawn(&data_fail);
    start_args_deinit(&data_fail.base);
    assert(thread_id < 0 && "Thread creation should fail");

    printf("Unlock created threads\n");
    for (int i = 0; i < MAX_NUM_THREADS; i++) {
        __atomic_store_n(&data[i].th_continue, 1, __ATOMIC_SEQ_CST);
        __builtin_wasm_memory_atomic_notify(&data[i].th_continue, 1);
    }

    printf("Wait for threads to finish\n");
    for (int i = 0; i < MAX_NUM_THREADS; i++) {
        if (__builtin_wasm_memory_atomic_wait32(&data[i].th_done, 0, TIMEOUT)
            == 2) {
            assert(false && "Wait should not time out");
        }

        start_args_deinit(&data[i].base);
    }

    printf("Value of count after update: %d\n", g_count);
    assert(g_count == (MAX_NUM_THREADS)
           && "Global count not updated correctly");

    /* --------------------------------------------------- */

    printf("Create new threads without waiting from them to finish\n");
    shared_t data_no_join[MAX_NUM_THREADS] = { 0 };
    for (int i = 0; i < MAX_NUM_THREADS; i++) {
        /* No graceful memory free to simplify the test */
        assert(start_args_init(&data_no_join[i].base));
        data_no_join[i].no_ops = true;

        int thread_id = -1;
        for (int j = 0; j < NUM_RETRY && thread_id < 0; j++) {
            thread_id = __wasi_thread_spawn(&data_no_join[i]);
            if (thread_id < 0)
                __builtin_wasm_memory_atomic_wait32(NULL, 0, SECOND);
        }

        printf("Thread created with id=%d\n", thread_id);
        assert(thread_id > 0 && "Thread creation should succeed");
    }

    return EXIT_SUCCESS;
}
