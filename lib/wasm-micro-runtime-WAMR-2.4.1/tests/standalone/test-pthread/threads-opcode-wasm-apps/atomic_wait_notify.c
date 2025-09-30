/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>

#define MAX_NUM_THREADS 4
#define NUM_ITER 100000

int g_val;
int my_mutex;

int
try_lock()
{
    return __atomic_compare_exchange(&my_mutex, &(int){ 0 }, &(int){ 1 }, false,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

void
lock_acquire()
{
    while (!try_lock()) {
        // expected value (1 => locked)
        __builtin_wasm_memory_atomic_wait32(&my_mutex, 1, -1);
    }
}
void
lock_release()
{
    // unlock the mutex
    __atomic_store(&my_mutex, &(int){ 0 }, __ATOMIC_SEQ_CST);
    // notify 1 waiter
    __builtin_wasm_memory_atomic_notify(&my_mutex, 1);
}

static void *
thread(void *arg)
{
    for (int i = 0; i < NUM_ITER; i++) {
        lock_acquire();
        g_val++;
        lock_release();
    }

    return NULL;
}

int
main()
{
    pthread_t tids[MAX_NUM_THREADS];

    for (int i = 0; i < MAX_NUM_THREADS; i++) {
        if (pthread_create(&tids[i], NULL, thread, NULL) != 0) {
            printf("Thread creation failed\n");
        }
    }

    for (int i = 0; i < MAX_NUM_THREADS; i++) {
        if (pthread_join(tids[i], NULL) != 0) {
            printf("Thread join failed\n");
        }
    }

    printf("Value of counter after add update: %d (expected=%d)\n", g_val,
           MAX_NUM_THREADS * NUM_ITER);
    if (g_val != MAX_NUM_THREADS * NUM_ITER) {
        __builtin_trap();
    }

    return 0;
}