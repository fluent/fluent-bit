/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <pthread.h>

static pthread_mutex_t mutex;
static pthread_cond_t cond;

static void *
thread(void *arg)
{
    int *num = (int *)arg;

    pthread_mutex_lock(&mutex);
    printf("thread start \n");

    for (int i = 0; i < 10; i++) {
        *num = *num + 1;
        printf("num: %d\n", *num);
    }

    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);

    printf("thread exit \n");

    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t tid;
    int num = 0, ret = -1;

    if (pthread_mutex_init(&mutex, NULL) != 0) {
        printf("Failed to init mutex.\n");
        return -1;
    }
    if (pthread_cond_init(&cond, NULL) != 0) {
        printf("Failed to init cond.\n");
        goto fail1;
    }

    pthread_mutex_lock(&mutex);
    if (pthread_create(&tid, NULL, thread, &num) != 0) {
        printf("Failed to create thread.\n");
        goto fail2;
    }

    printf("cond wait start\n");
    pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);
    printf("cond wait success.\n");

    if (pthread_join(tid, NULL) != 0) {
        printf("Failed to join thread.\n");
    }

    ret = 0;

fail2:
    pthread_cond_destroy(&cond);
fail1:
    pthread_mutex_destroy(&mutex);

    return ret;
}