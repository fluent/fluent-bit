/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <pthread.h>
#include <stdio.h>

/* Start function for the background thread */
void *
bg_func(void *arg)
{
    printf("Thread start.\n");
    /* This thread will never exit unless canceled by other thread */
    while (1)
        ;
}

/* Foreground thread and main entry point */
int
main(int argc, char *argv[])
{
    pthread_t bg_thread;

    if (pthread_create(&bg_thread, NULL, bg_func, NULL)) {
        printf("Thread create failed");
        return 1;
    }
    printf("Thread created.\n");

    /* Cancel the sub thread */
    pthread_cancel(bg_thread);

    printf("Sub-thread Canceled.\n");
    printf("Test success.\n");

    return 0;
}
