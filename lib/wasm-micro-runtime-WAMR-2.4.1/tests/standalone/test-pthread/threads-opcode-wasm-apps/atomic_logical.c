/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <stdio.h>
#include <pthread.h>

// x XOR x -> 0
// even num of thread -> g_val should end up with its original value
#define MAX_NUM_THREADS 4
#define NUM_ITER 199999

int g_val = 5050;

static void *
thread(void *arg)
{
    for (int i = 0; i < NUM_ITER; i++) {
        __atomic_fetch_xor(&g_val, i, __ATOMIC_SEQ_CST);
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

    printf("Global value after update: %d (expected=%d)\n", g_val, 5050);
    if (g_val != 5050) {
        __builtin_trap();
    }

    return -1;
}