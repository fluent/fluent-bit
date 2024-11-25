/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#ifndef __wasi__
#error This example only compiles to WASM/WASI target
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "wasi_thread_start.h"

static const int64_t SECOND = 1000 * 1000 * 1000;

typedef struct {
    start_args_t base;
    int th_ready;
    int value;
    int thread_id;
} shared_t;

void
__wasi_thread_start_C(int thread_id, int *start_arg)
{
    shared_t *data = (shared_t *)start_arg;

    printf("New thread ID: %d, starting parameter: %d\n", thread_id,
           data->value);

    data->thread_id = thread_id;
    data->value += 8;
    printf("Updated value: %d\n", data->value);

    __atomic_store_n(&data->th_ready, 1, __ATOMIC_SEQ_CST);
    __builtin_wasm_memory_atomic_notify(&data->th_ready, 1);
}

int
main(int argc, char **argv)
{
    shared_t data = { { NULL }, 0, 52, -1 };
    int thread_id;
    int ret = EXIT_SUCCESS;

    if (!start_args_init(&data.base)) {
        printf("Stack allocation for thread failed\n");
        return EXIT_FAILURE;
    }

    thread_id = __wasi_thread_spawn(&data);
    ASSERT_VALID_TID(thread_id);

    if (__builtin_wasm_memory_atomic_wait32(&data.th_ready, 0, SECOND) == 2) {
        printf("Timeout\n");
        return EXIT_FAILURE;
    }

    printf("Thread completed, new value: %d, thread id: %d\n", data.value,
           data.thread_id);

    assert(thread_id == data.thread_id);

    start_args_deinit(&data.base);

    return ret;
}
