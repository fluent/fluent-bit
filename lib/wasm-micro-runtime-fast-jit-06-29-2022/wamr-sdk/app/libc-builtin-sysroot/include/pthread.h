/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WAMR_LIB_PTHREAD_H
#define _WAMR_LIB_PTHREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Data type define of pthread, mutex, cond and key */
typedef unsigned int pthread_t;
typedef unsigned int pthread_mutex_t;
typedef unsigned int pthread_cond_t;
typedef unsigned int pthread_key_t;

/* Thread APIs */
int
pthread_create(pthread_t *thread, const void *attr,
               void *(*start_routine)(void *), void *arg);

int
pthread_join(pthread_t thread, void **retval);

int
pthread_detach(pthread_t thread);

int
pthread_cancel(pthread_t thread);

pthread_t
pthread_self(void);

void
pthread_exit(void *retval);

/* Mutex APIs */
int
pthread_mutex_init(pthread_mutex_t *mutex, const void *attr);

int
pthread_mutex_lock(pthread_mutex_t *mutex);

int
pthread_mutex_unlock(pthread_mutex_t *mutex);

int
pthread_mutex_destroy(pthread_mutex_t *mutex);

/* Cond APIs */
int
pthread_cond_init(pthread_cond_t *cond, const void *attr);

int
pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

int
pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                       uint64_t useconds);

int
pthread_cond_signal(pthread_cond_t *cond);

int
pthread_cond_broadcast(pthread_cond_t *cond);

int
pthread_cond_destroy(pthread_cond_t *cond);

/* Pthread key APIs */
int
pthread_key_create(pthread_key_t *key, void (*destructor)(void *));

int
pthread_setspecific(pthread_key_t key, const void *value);

void *
pthread_getspecific(pthread_key_t key);

int
pthread_key_delete(pthread_key_t key);

#ifdef __cplusplus
}
#endif

#endif /* end of _WAMR_LIB_PTHREAD_H */
