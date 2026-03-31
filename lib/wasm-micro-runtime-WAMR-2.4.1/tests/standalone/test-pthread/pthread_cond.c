/*
 * Copyright (C) 2023 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

pthread_mutex_t mutex;
static pthread_cond_t cond;

typedef struct test {
    int test1;
    int test2;
} Test;

Test t1;

void *
thread(void *arg)
{
    pthread_mutex_lock(&mutex);
    printf("thread signal\n");
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);

    return NULL;
}

int
main()
{
    pthread_t p;

    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    printf("parent begin\n");

    pthread_mutex_lock(&mutex);
    pthread_create(&p, NULL, thread, NULL);

    pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);

    printf("parend end\n");

    pthread_join(p, NULL);

    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&mutex);

    return 0;
}