/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include "peterson.h"

void
peterson_lock_acquire(peterson_lock_t *lock, int thread_id)
{
    bool xchg_ret1;
    int xchg_ret2;
    // this threads wants to enter the cs
    __atomic_exchange(&lock->flag[thread_id], &(bool){ true }, &xchg_ret1,
                      __ATOMIC_SEQ_CST);

    // assume the other thread has priority
    int other_thread = 1 - thread_id;

    __atomic_exchange(&lock->turn, &other_thread, &xchg_ret2, __ATOMIC_SEQ_CST);

    while (lock->turn == other_thread && lock->flag[other_thread]) {
        // Busy wait
    }
}

int
main()
{
    pthread_t thread1, thread2;

    printf("============ test peterson lock using atomic xchg ============\n");
    run_test(&thread1, &thread2, test_peterson_lock_atomicity);

    return 0;
}