/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

#ifndef SGX_DISABLE_PTHREAD
typedef struct {
    thread_start_routine_t start;
    void *arg;
} thread_wrapper_arg;

static void *
os_thread_wrapper(void *arg)
{
    thread_wrapper_arg *targ = arg;
    thread_start_routine_t start_func = targ->start;
    void *thread_arg = targ->arg;

#if 0
    os_printf("THREAD CREATED %p\n", &targ);
#endif
    BH_FREE(targ);
    start_func(thread_arg);
    return NULL;
}

int
os_thread_create_with_prio(korp_tid *tid, thread_start_routine_t start,
                           void *arg, unsigned int stack_size, int prio)
{
    thread_wrapper_arg *targ;

    assert(tid);
    assert(start);

    targ = (thread_wrapper_arg *)BH_MALLOC(sizeof(*targ));
    if (!targ) {
        return BHT_ERROR;
    }

    targ->start = start;
    targ->arg = arg;

    if (pthread_create(tid, NULL, os_thread_wrapper, targ) != 0) {
        BH_FREE(targ);
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_thread_create(korp_tid *tid, thread_start_routine_t start, void *arg,
                 unsigned int stack_size)
{
    return os_thread_create_with_prio(tid, start, arg, stack_size,
                                      BH_THREAD_DEFAULT_PRIORITY);
}
#endif

korp_tid
os_self_thread()
{
#ifndef SGX_DISABLE_PTHREAD
    return pthread_self();
#else
    return 0;
#endif
}

int
os_mutex_init(korp_mutex *mutex)
{
#ifndef SGX_DISABLE_PTHREAD
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    *mutex = m;
#endif
    return BHT_OK;
}

int
os_mutex_destroy(korp_mutex *mutex)
{
#ifndef SGX_DISABLE_PTHREAD
    pthread_mutex_destroy(mutex);
#endif
    return BHT_OK;
}

int
os_mutex_lock(korp_mutex *mutex)
{
#ifndef SGX_DISABLE_PTHREAD
    return pthread_mutex_lock(mutex);
#else
    return 0;
#endif
}

int
os_mutex_unlock(korp_mutex *mutex)
{
#ifndef SGX_DISABLE_PTHREAD
    return pthread_mutex_unlock(mutex);
#else
    return 0;
#endif
}

int
os_cond_init(korp_cond *cond)
{
#ifndef SGX_DISABLE_PTHREAD
    pthread_cond_t c = PTHREAD_COND_INITIALIZER;
    *cond = c;
#endif
    return BHT_OK;
}

int
os_cond_destroy(korp_cond *cond)
{
#ifndef SGX_DISABLE_PTHREAD
    pthread_cond_destroy(cond);
#endif
    return BHT_OK;
}

int
os_cond_wait(korp_cond *cond, korp_mutex *mutex)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(cond);
    assert(mutex);

    if (pthread_cond_wait(cond, mutex) != BHT_OK)
        return BHT_ERROR;

#endif
    return BHT_OK;
}

int
os_cond_reltimedwait(korp_cond *cond, korp_mutex *mutex, uint64 useconds)
{
    os_printf("warning: SGX pthread_cond_timedwait isn't supported, "
              "calling pthread_cond_wait instead!\n");
    return BHT_ERROR;
}

int
os_cond_signal(korp_cond *cond)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(cond);

    if (pthread_cond_signal(cond) != BHT_OK)
        return BHT_ERROR;

#endif
    return BHT_OK;
}

int
os_cond_broadcast(korp_cond *cond)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(cond);

    if (pthread_cond_broadcast(cond) != BHT_OK)
        return BHT_ERROR;

#endif
    return BHT_OK;
}

int
os_thread_join(korp_tid thread, void **value_ptr)
{
#ifndef SGX_DISABLE_PTHREAD
    return pthread_join(thread, value_ptr);
#else
    return 0;
#endif
}

int
os_thread_detach(korp_tid thread)
{
    /* SGX pthread_detach isn't provided, return directly. */
    return 0;
}

void
os_thread_exit(void *retval)
{
#ifndef SGX_DISABLE_PTHREAD
    pthread_exit(retval);
#else
    return;
#endif
}

uint8 *
os_thread_get_stack_boundary()
{
    /* TODO: get sgx stack boundary */
    return NULL;
}

void
os_thread_jit_write_protect_np(bool enabled)
{}

int
os_rwlock_init(korp_rwlock *lock)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(lock);

    if (pthread_rwlock_init(lock, NULL) != BHT_OK)
        return BHT_ERROR;
#endif

    return BHT_OK;
}

int
os_rwlock_rdlock(korp_rwlock *lock)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(lock);

    if (pthread_rwlock_rdlock(lock) != BHT_OK)
        return BHT_ERROR;
#endif

    return BHT_OK;
}

int
os_rwlock_wrlock(korp_rwlock *lock)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(lock);

    if (pthread_rwlock_wrlock(lock) != BHT_OK)
        return BHT_ERROR;
#endif

    return BHT_OK;
}

int
os_rwlock_unlock(korp_rwlock *lock)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(lock);

    if (pthread_rwlock_unlock(lock) != BHT_OK)
        return BHT_ERROR;
#endif

    return BHT_OK;
}

int
os_rwlock_destroy(korp_rwlock *lock)
{
#ifndef SGX_DISABLE_PTHREAD
    assert(lock);

    if (pthread_rwlock_destroy(lock) != BHT_OK)
        return BHT_ERROR;
#endif

    return BHT_OK;
}
