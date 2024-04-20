/*
 * Copyright (C) 2023 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void
set_context(int32_t n) __attribute__((import_module("env")))
__attribute__((import_name("set_context")));

int32_t
get_context() __attribute__((import_module("env")))
__attribute__((import_name("get_context")));

void *
start(void *vp)
{
    int32_t v;

    printf("thread started\n");

    printf("confirming the initial state on thread\n");
    v = get_context();
    assert(v == -1);

    printf("setting the context on thread\n");
    set_context(1234);

    printf("confirming the context on thread\n");
    v = get_context();
    assert(v == 1234);
    return NULL;
}

int
main()
{
    pthread_t t1;
    int32_t v;
    int ret;

    printf("confirming the initial state on main\n");
    v = get_context();
    assert(v == -1);

    printf("creating a thread\n");
    ret = pthread_create(&t1, NULL, start, NULL);
    assert(ret == 0);
    void *val;
    ret = pthread_join(t1, &val);
    assert(ret == 0);
    printf("joined the thread\n");

    printf("confirming the context propagated from the thread on main\n");
    v = get_context();
    assert(v == 1234);

    printf("success\n");
    return 0;
}
