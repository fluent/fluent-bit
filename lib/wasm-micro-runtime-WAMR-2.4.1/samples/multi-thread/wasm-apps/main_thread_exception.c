/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <pthread.h>

typedef struct ThreadArgs {
    int start;
    int length;
} ThreadArgs;

void *
thread(void *args)
{
    while (1) {
        /* When other threads (including main thread) throw exception,
            this thread can successfully exit the dead loop */
    }
}

int
main()
{
    pthread_t tids;

    if (pthread_create(&tids, NULL, thread, NULL) != 0) {
        printf("pthread_create failed\n");
    }

    /* Trigger an exception */
    __builtin_trap();

    return 0;
}
