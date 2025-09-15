/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <pthread.h>

#define MAX_NUM_THREADS 4
#define NUM_ITER 100000

int g_add_count = 0;
int g_sub_count = 0;

static void *
thread(void *arg)
{
    for (int i = 0; i < NUM_ITER; i++) {
        __atomic_fetch_add(&g_add_count, 1, __ATOMIC_SEQ_CST);
        __atomic_fetch_sub(&g_sub_count, 1, __ATOMIC_SEQ_CST);
    }

    return NULL;
}

int
main(int argc, char **argv)
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

    printf("Value of counter after add update: %d (expected=%d)\n", g_add_count,
           MAX_NUM_THREADS * NUM_ITER);
    if (g_add_count != MAX_NUM_THREADS * NUM_ITER) {
        __builtin_trap();
    }

    printf("Value of counter after sub update: %d (expected=%d)\n", g_sub_count,
           -(MAX_NUM_THREADS * NUM_ITER));
    if (g_sub_count != -(MAX_NUM_THREADS * NUM_ITER)) {
        __builtin_trap();
    }

    return -1;
}