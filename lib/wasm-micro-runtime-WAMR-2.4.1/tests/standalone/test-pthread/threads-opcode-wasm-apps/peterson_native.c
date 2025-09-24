/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include "peterson.h"

void
peterson_lock_acquire(peterson_lock_t *lock, int thread_id)
{
    // this threads wants to enter the cs
    lock->flag[thread_id] = true;

    // assume the other thread has priority
    int other_thread = 1 - thread_id;

    lock->turn = other_thread;

    while (lock->turn == other_thread && lock->flag[other_thread]) {
        // Busy wait
    }
}

int
main()
{
    pthread_t thread1, thread2;

    printf("============ test naive peterson lock(should trap) ============\n");
    printf("============ May not be able to observe in interpreter mode "
           "============\n");
    run_test(&thread1, &thread2, test_peterson_lock_atomicity);

    return 0;
}