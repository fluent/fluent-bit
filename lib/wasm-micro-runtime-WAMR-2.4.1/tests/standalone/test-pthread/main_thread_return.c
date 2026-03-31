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
    uint32_t i;

    printf("Thread start.\n");

    for (i = 0; i < 100000000; i++)
        arg += i;
    return arg;
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

    /* Return the process directly, runtime should terminate
        the sub threads and exit the whole wasm module */
    printf("Process exit.\n");
    printf("Test success.\n");

    return 0;
}
