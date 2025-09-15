/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>

// Peterson's algorithm for mutual exclusion
#define ITERATIONS 15000000

typedef struct {
    bool flag[2];
    int turn;
} peterson_lock_t;

static int counter = 0;
static peterson_lock_t lock;

void
peterson_lock_acquire(peterson_lock_t *lock, int thread_id);

void
peterson_lock_release(peterson_lock_t *lock, int thread_id)
{
    lock->flag[thread_id] = false;
}

void *
test_peterson_lock_atomicity(void *arg)
{
    int thread_id = (int)(long)arg;

    for (int i = 0; i < ITERATIONS; ++i) {
        peterson_lock_acquire(&lock, thread_id);
        counter++;
        peterson_lock_release(&lock, thread_id);
    }

    return NULL;
}

int
run_test(pthread_t *thread1_ptr, pthread_t *thread2_ptr,
         void *(*start_routine)(void *))
{
    lock.flag[0] = false;
    lock.flag[1] = false;
    lock.turn = 0;
    counter = 0;

    pthread_create(thread1_ptr, NULL, start_routine, (void *)0);
    pthread_create(thread2_ptr, NULL, start_routine, (void *)1);

    pthread_join(*thread1_ptr, NULL);
    pthread_join(*thread2_ptr, NULL);

    printf("Expected counter value: %d\n", ITERATIONS * 2);
    printf("Actual counter value: %d\n", counter);
    if (counter != ITERATIONS * 2)
        __builtin_trap();

    return 0;
}