/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "sgx_pthread.h"
#include "sgx_error.h"

#ifndef SGX_DISABLE_WASI

#define TRACE_FUNC() os_printf("undefined %s\n", __FUNCTION__)
#define TRACE_OCALL_FAIL() os_printf("ocall %s failed!\n", __FUNCTION__)

#ifndef SGX_THREAD_LOCK_INITIALIZER /* defined since sgxsdk-2.11 */
/* sgxsdk doesn't support pthread_rwlock related APIs until
   version 2.11, we implement them by ourselves. */
int
ocall_pthread_rwlock_init(int *p_ret, void **rwlock, void *attr);

int
ocall_pthread_rwlock_destroy(int *p_ret, void **rwlock);

int
ocall_pthread_rwlock_rdlock(int *p_ret, void **rwlock);

int
ocall_pthread_rwlock_wrlock(int *p_ret, void **rwlock);

int
ocall_pthread_rwlock_unlock(int *p_ret, void **rwlock);

int
pthread_rwlock_init(pthread_rwlock_t *rwlock, void *attr)
{
    int ret = -1;

    if (ocall_pthread_rwlock_init(&ret, (void **)rwlock, NULL) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    (void)attr;
    return ret;
}

int
pthread_rwlock_destroy(pthread_rwlock_t *rwlock)
{
    int ret = -1;

    if (ocall_pthread_rwlock_destroy(&ret, (void *)*rwlock) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
    }
    return ret;
}

int
pthread_rwlock_rdlock(pthread_rwlock_t *rwlock)
{
    int ret = -1;

    if (ocall_pthread_rwlock_rdlock(&ret, (void *)*rwlock) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
    }
    return ret;
}

int
pthread_rwlock_wrlock(pthread_rwlock_t *rwlock)
{
    int ret = -1;

    if (ocall_pthread_rwlock_wrlock(&ret, (void *)*rwlock) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
    }
    return ret;
}

int
pthread_rwlock_unlock(pthread_rwlock_t *rwlock)
{
    int ret = -1;

    if (ocall_pthread_rwlock_unlock(&ret, (void *)*rwlock) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
    }
    return ret;
}
#endif /* end of SGX_THREAD_LOCK_INITIALIZER */

#endif
