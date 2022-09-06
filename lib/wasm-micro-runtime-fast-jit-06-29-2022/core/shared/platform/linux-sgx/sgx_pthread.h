/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SGX_PTHREAD_H
#define _SGX_PTHREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SGX_THREAD_LOCK_INITIALIZER /* defined since sgxsdk-2.11 */
/* sgxsdk doesn't support pthread_rwlock related APIs until
   version 2.11, we implement them by ourselves. */
typedef uintptr_t pthread_rwlock_t;

int
pthread_rwlock_init(pthread_rwlock_t *rwlock, void *attr);
int
pthread_rwlock_destroy(pthread_rwlock_t *rwlock);

int
pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
int
pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int
pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
#endif /* end of SGX_THREAD_LOCK_INITIALIZER */

#ifdef __cplusplus
}
#endif

#endif /* end of _SGX_PTHREAD_H */
