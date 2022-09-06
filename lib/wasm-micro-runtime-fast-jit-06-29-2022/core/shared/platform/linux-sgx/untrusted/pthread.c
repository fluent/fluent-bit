/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include <pthread.h>

int
ocall_pthread_rwlock_init(void **rwlock, void *attr)
{
    int ret = 0;

    *rwlock = malloc(sizeof(pthread_rwlock_t));
    if (*rwlock == NULL)
        return -1;

    ret = pthread_rwlock_init((pthread_rwlock_t *)*rwlock, NULL);
    if (ret != 0) {
        free(*rwlock);
        *rwlock = NULL;
    }
    (void)attr;
    return ret;
}

int
ocall_pthread_rwlock_destroy(void *rwlock)
{
    pthread_rwlock_t *lock = (pthread_rwlock_t *)rwlock;
    int ret;

    ret = pthread_rwlock_destroy(lock);
    free(lock);
    return ret;
}

int
ocall_pthread_rwlock_rdlock(void *rwlock)
{
    return pthread_rwlock_rdlock((pthread_rwlock_t *)rwlock);
}

int
ocall_pthread_rwlock_wrlock(void *rwlock)
{
    return pthread_rwlock_wrlock((pthread_rwlock_t *)rwlock);
}

int
ocall_pthread_rwlock_unlock(void *rwlock)
{
    return pthread_rwlock_unlock((pthread_rwlock_t *)rwlock);
}
