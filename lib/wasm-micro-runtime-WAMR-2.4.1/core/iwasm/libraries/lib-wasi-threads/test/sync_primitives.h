/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdbool.h>

/* Mutex */

typedef int pthread_mutex_t;

int
pthread_mutex_init(pthread_mutex_t *mutex, void *unused)
{
    *mutex = 0;
    return 0;
}

int
pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    return 0;
}

static bool
try_pthread_mutex_lock(pthread_mutex_t *mutex)
{
    int expected = 0;
    return __atomic_compare_exchange_n(mutex, &expected, 1, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

int
pthread_mutex_lock(pthread_mutex_t *mutex)
{
    while (!try_pthread_mutex_lock(mutex))
        __builtin_wasm_memory_atomic_wait32(mutex, 1, -1);
    return 0;
}

int
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    __atomic_store_n(mutex, 0, __ATOMIC_SEQ_CST);
    __builtin_wasm_memory_atomic_notify(mutex, 1);
    return 0;
}

/* Barrier */

typedef struct {
    int count;
    int num_threads;
    int mutex;
    int ready;
} pthread_barrier_t;

int
pthread_barrier_init(pthread_barrier_t *barrier, void *unused, int num_threads)
{
    barrier->count = 0;
    barrier->num_threads = num_threads;
    barrier->ready = 0;
    pthread_mutex_init(&barrier->mutex, NULL);

    return 0;
}

int
pthread_barrier_wait(pthread_barrier_t *barrier)
{
    bool no_wait = false;
    int count;

    pthread_mutex_lock(&barrier->mutex);
    count = barrier->count++;
    if (barrier->count >= barrier->num_threads) {
        no_wait = true;
        barrier->count = 0;
    }
    pthread_mutex_unlock(&barrier->mutex);

    if (no_wait) {
        __atomic_store_n(&barrier->ready, 1, __ATOMIC_SEQ_CST);
        __builtin_wasm_memory_atomic_notify(&barrier->ready, count);
        return 0;
    }

    __builtin_wasm_memory_atomic_wait32(&barrier->ready, 0, -1);
    return 0;
}