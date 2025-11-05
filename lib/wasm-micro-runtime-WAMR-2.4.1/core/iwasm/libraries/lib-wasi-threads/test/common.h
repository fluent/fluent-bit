/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>

#if USE_CUSTOM_SYNC_PRIMITIVES != 0
#include "sync_primitives.h"
#else
#include <pthread.h>
#endif

#include "wasi_thread_start.h"

typedef enum {
    BLOCKING_TASK_BUSY_WAIT,
    BLOCKING_TASK_ATOMIC_WAIT,
    BLOCKING_TASK_POLL_ONEOFF
} blocking_task_type_t;

/* Parameter to change test behavior */
static bool termination_by_trap;
static bool termination_in_main_thread;
static blocking_task_type_t blocking_task_type;

#define NUM_THREADS 3
static pthread_barrier_t barrier;

typedef struct {
    start_args_t base;
    bool throw_exception;
} shared_t;

void
run_long_task()
{
    if (blocking_task_type == BLOCKING_TASK_BUSY_WAIT) {
        for (;;) {
        }
    }
    else if (blocking_task_type == BLOCKING_TASK_ATOMIC_WAIT) {
        __builtin_wasm_memory_atomic_wait32(0, 0, -1);
    }
    else {
        sleep(UINT_MAX);
    }
}

void
start_job()
{
    /* Wait for all threads (including the main thread) to be ready */
    pthread_barrier_wait(&barrier);
    run_long_task(); /* Task to be interrupted */
    assert(false && "Thread termination test failed");
}

void
terminate_process()
{
    /* Wait for all threads (including the main thread) to be ready */
    pthread_barrier_wait(&barrier);

    if (termination_by_trap)
        __builtin_trap();
    else
        __wasi_proc_exit(33);
}

void
__wasi_thread_start_C(int thread_id, int *start_arg)
{
    shared_t *data = (shared_t *)start_arg;

    if (data->throw_exception) {
        terminate_process();
    }
    else {
        start_job();
    }
}

void
test_termination(bool trap, bool main, blocking_task_type_t task_type)
{
    termination_by_trap = trap;
    termination_in_main_thread = main;
    blocking_task_type = task_type;

    int thread_id = -1, i;
    shared_t data[NUM_THREADS] = { 0 };
    assert(pthread_barrier_init(&barrier, NULL, NUM_THREADS + 1) == 0
           && "Failed to init barrier");

    for (i = 0; i < NUM_THREADS; i++) {
        /* No graceful memory free to simplify the test */
        assert(start_args_init(&data[i].base)
               && "Failed to allocate thread's stack");
    }

    /* Create a thread that forces termination through trap or `proc_exit` */
    data[0].throw_exception = !termination_in_main_thread;
    thread_id = __wasi_thread_spawn(&data[0]);
    assert(thread_id > 0 && "Failed to create thread");

    /* Create two additional threads to test exception propagation */
    data[1].throw_exception = false;
    thread_id = __wasi_thread_spawn(&data[1]);
    assert(thread_id > 0 && "Failed to create thread");
    data[2].throw_exception = false;
    thread_id = __wasi_thread_spawn(&data[2]);
    assert(thread_id > 0 && "Failed to create thread");

    if (termination_in_main_thread) {
        terminate_process();
    }
    else {
        start_job();
    }
}