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
    while (1) {
        pthread_exit(NULL);
    }
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

    /* Wait for background thread to finish */
    if (pthread_join(bg_thread, NULL)) {
        printf("Thread join failed");
        return 2;
    }

    printf("Sub-thread exit.\n");
    printf("Test success.\n");

    return 0;
}
