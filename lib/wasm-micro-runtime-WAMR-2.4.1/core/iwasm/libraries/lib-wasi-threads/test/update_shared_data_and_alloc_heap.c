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
#include <pthread.h>

#include "wasi_thread_start.h"

enum CONSTANTS {
    NUM_THREADS = 4,
    NUM_ITER = 30,
    SECOND = 1000 * 1000 * 1000, /* 1 second */
    TIMEOUT = 10LL * SECOND
};

typedef struct {
    start_args_t base;
    int th_done;
    int *count;
    int iteration;
    int *pval;
} shared_t;

pthread_mutex_t mutex;
int *vals[NUM_THREADS];

void
__wasi_thread_start_C(int thread_id, int *start_arg)
{
    shared_t *data = (shared_t *)start_arg;

    for (int i = 0; i < NUM_ITER; i++)
        __atomic_fetch_add(data->count, 1, __ATOMIC_SEQ_CST);

    *vals[data->iteration] = data->iteration;

    __atomic_store_n(&data->th_done, 1, __ATOMIC_SEQ_CST);
    __builtin_wasm_memory_atomic_notify(&data->th_done, 1);
}

int
main(int argc, char **argv)
{
    shared_t data[NUM_THREADS] = { 0 };
    int thread_ids[NUM_THREADS];
    int *count = calloc(1, sizeof(int));

    assert(count != NULL && "Failed to call calloc");
    assert(pthread_mutex_init(&mutex, NULL) == 0 && "Failed to init mutex");

    for (int i = 0; i < NUM_THREADS; i++) {
        vals[i] = malloc(sizeof(int));
        assert(vals[i] != NULL && "Failed to call calloc");
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        assert(start_args_init(&data[i].base)
               && "Stack allocation for thread failed");
        __atomic_store_n(&data[i].count, count, __ATOMIC_SEQ_CST);
        data[i].iteration = i;

        thread_ids[i] = __wasi_thread_spawn(&data[i]);
        ASSERT_VALID_TID(thread_ids[i]);
    }

    printf("Wait for threads to finish\n");
    for (int i = 0; i < NUM_THREADS; i++) {
        if (__builtin_wasm_memory_atomic_wait32(&data[i].th_done, 0, TIMEOUT)
            == 2) {
            assert(false && "Wait should not time out");
        }

        start_args_deinit(&data[i].base);
    }

    assert(*count == (NUM_THREADS * NUM_ITER) && "Count not updated correctly");

    for (int i = 0; i < NUM_THREADS; i++) {
        printf("val=%d\n", *vals[i]);
        assert(*vals[i] == i && "Value not updated correctly");
        free(vals[i]);
    }

    free(count);
    assert(pthread_mutex_destroy(&mutex) == 0 && "Failed to destroy mutex");

    return EXIT_SUCCESS;
}
