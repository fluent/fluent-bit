/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

#define bh_assert(v) assert(v)

#define BH_SEM_COUNT_MAX 0xFFFF

struct os_thread_data;

typedef struct os_thread_wait_node {
    korp_sem sem;
    void *retval;
    os_thread_wait_list next;
} os_thread_wait_node;

typedef struct os_thread_data {
    /* Next thread data */
    struct os_thread_data *next;
    /* Thread data of parent thread */
    struct os_thread_data *parent;
    /* Thread Id */
    DWORD thread_id;
    /* Thread start routine */
    thread_start_routine_t start_routine;
    /* Thread start routine argument */
    void *arg;
    /* Wait node of current thread */
    os_thread_wait_node wait_node;
    /* Wait cond */
    korp_cond wait_cond;
    /* Wait lock */
    korp_mutex wait_lock;
    /* Waiting list of other threads who are joining this thread */
    os_thread_wait_list thread_wait_list;
    /* End node of the waiting list */
    os_thread_wait_node *thread_wait_list_end;
    /* Whether the thread has exited */
    bool thread_exited;
    /* Thread return value */
    void *thread_retval;
} os_thread_data;

static bool is_thread_sys_inited = false;

/* Thread data of supervisor thread */
static os_thread_data supervisor_thread_data;

/* Thread data list lock */
static korp_mutex thread_data_list_lock;

/* Thread data key */
static DWORD thread_data_key;

/* The GetCurrentThreadStackLimits API from "kernel32" */
static void(WINAPI *GetCurrentThreadStackLimits_Kernel32)(PULONG_PTR,
                                                          PULONG_PTR) = NULL;

int
os_sem_init(korp_sem *sem);
int
os_sem_destroy(korp_sem *sem);
int
os_sem_wait(korp_sem *sem);
int
os_sem_reltimed_wait(korp_sem *sem, uint64 useconds);
int
os_sem_signal(korp_sem *sem);

int
os_thread_sys_init()
{
    HMODULE module;

    if (is_thread_sys_inited)
        return BHT_OK;

    if ((thread_data_key = TlsAlloc()) == TLS_OUT_OF_INDEXES)
        return BHT_ERROR;

    /* Initialize supervisor thread data */
    memset(&supervisor_thread_data, 0, sizeof(os_thread_data));

    supervisor_thread_data.thread_id = GetCurrentThreadId();

    if (os_sem_init(&supervisor_thread_data.wait_node.sem) != BHT_OK)
        goto fail1;

    if (os_mutex_init(&supervisor_thread_data.wait_lock) != BHT_OK)
        goto fail2;

    if (os_cond_init(&supervisor_thread_data.wait_cond) != BHT_OK)
        goto fail3;

    if (!TlsSetValue(thread_data_key, &supervisor_thread_data))
        goto fail4;

    if (os_mutex_init(&thread_data_list_lock) != BHT_OK)
        goto fail5;

    if ((module = GetModuleHandle((LPCTSTR) "kernel32"))) {
        *(void **)&GetCurrentThreadStackLimits_Kernel32 =
            GetProcAddress(module, "GetCurrentThreadStackLimits");
    }

    is_thread_sys_inited = true;
    return BHT_OK;

fail5:
    TlsSetValue(thread_data_key, NULL);
fail4:
    os_cond_destroy(&supervisor_thread_data.wait_cond);
fail3:
    os_mutex_destroy(&supervisor_thread_data.wait_lock);
fail2:
    os_sem_destroy(&supervisor_thread_data.wait_node.sem);
fail1:
    TlsFree(thread_data_key);
    return BHT_ERROR;
}

void
os_thread_sys_destroy()
{
    if (is_thread_sys_inited) {
        os_thread_data *thread_data, *thread_data_next;

        thread_data = supervisor_thread_data.next;
        while (thread_data) {
            thread_data_next = thread_data->next;

            /* Destroy resources of thread data */
            os_cond_destroy(&thread_data->wait_cond);
            os_sem_destroy(&thread_data->wait_node.sem);
            os_mutex_destroy(&thread_data->wait_lock);
            BH_FREE(thread_data);

            thread_data = thread_data_next;
        }

        os_mutex_destroy(&thread_data_list_lock);
        os_cond_destroy(&supervisor_thread_data.wait_cond);
        os_mutex_destroy(&supervisor_thread_data.wait_lock);
        os_sem_destroy(&supervisor_thread_data.wait_node.sem);
        memset(&supervisor_thread_data, 0, sizeof(os_thread_data));
        TlsFree(thread_data_key);
        thread_data_key = 0;
        is_thread_sys_inited = false;
    }
}

static os_thread_data *
thread_data_current()
{
    return (os_thread_data *)TlsGetValue(thread_data_key);
}

static void
os_thread_cleanup(void *retval)
{
    os_thread_data *thread_data = thread_data_current();

    bh_assert(thread_data != NULL);

    os_mutex_lock(&thread_data->wait_lock);
    if (thread_data->thread_wait_list) {
        /* Signal each joining thread */
        os_thread_wait_list head = thread_data->thread_wait_list;
        while (head) {
            os_thread_wait_list next = head->next;
            head->retval = retval;
            os_sem_signal(&head->sem);
            head = next;
        }
        thread_data->thread_wait_list = thread_data->thread_wait_list_end =
            NULL;
    }
    /* Set thread status and thread return value */
    thread_data->thread_exited = true;
    thread_data->thread_retval = retval;
    os_mutex_unlock(&thread_data->wait_lock);
}

static unsigned __stdcall os_thread_wrapper(void *arg)
{
    os_thread_data *thread_data = arg;
    os_thread_data *parent = thread_data->parent;
    void *retval;
    bool result;

#if 0
    os_printf("THREAD CREATED %p\n", thread_data);
#endif

    os_mutex_lock(&parent->wait_lock);
    thread_data->thread_id = GetCurrentThreadId();
    result = TlsSetValue(thread_data_key, thread_data);
#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (result)
        result = os_thread_signal_init() == 0 ? true : false;
#endif
    /* Notify parent thread */
    os_cond_signal(&parent->wait_cond);
    os_mutex_unlock(&parent->wait_lock);

    if (!result)
        return -1;

    retval = thread_data->start_routine(thread_data->arg);

    os_thread_cleanup(retval);
    return 0;
}

int
os_thread_create_with_prio(korp_tid *p_tid, thread_start_routine_t start,
                           void *arg, unsigned int stack_size, int prio)
{
    os_thread_data *parent = thread_data_current();
    os_thread_data *thread_data;

    if (!p_tid || !start)
        return BHT_ERROR;

    if (stack_size < BH_APPLET_PRESERVED_STACK_SIZE)
        stack_size = BH_APPLET_PRESERVED_STACK_SIZE;

    if (!(thread_data = BH_MALLOC(sizeof(os_thread_data))))
        return BHT_ERROR;

    memset(thread_data, 0, sizeof(os_thread_data));
    thread_data->parent = parent;
    thread_data->start_routine = start;
    thread_data->arg = arg;

    if (os_sem_init(&thread_data->wait_node.sem) != BHT_OK)
        goto fail1;

    if (os_mutex_init(&thread_data->wait_lock) != BHT_OK)
        goto fail2;

    if (os_cond_init(&thread_data->wait_cond) != BHT_OK)
        goto fail3;

    os_mutex_lock(&parent->wait_lock);
    if (!_beginthreadex(NULL, stack_size, os_thread_wrapper, thread_data, 0,
                        NULL)) {
        os_mutex_unlock(&parent->wait_lock);
        goto fail4;
    }

    /* Add thread data into thread data list */
    os_mutex_lock(&thread_data_list_lock);
    thread_data->next = supervisor_thread_data.next;
    supervisor_thread_data.next = thread_data;
    os_mutex_unlock(&thread_data_list_lock);

    /* Wait for the thread routine to set thread_data's tid
       and add thread_data to thread data list */
    os_cond_wait(&parent->wait_cond, &parent->wait_lock);
    os_mutex_unlock(&parent->wait_lock);

    *p_tid = (korp_tid)thread_data;
    return BHT_OK;

fail4:
    os_cond_destroy(&thread_data->wait_cond);
fail3:
    os_mutex_destroy(&thread_data->wait_lock);
fail2:
    os_sem_destroy(&thread_data->wait_node.sem);
fail1:
    BH_FREE(thread_data);
    return BHT_ERROR;
}

int
os_thread_create(korp_tid *tid, thread_start_routine_t start, void *arg,
                 unsigned int stack_size)
{
    return os_thread_create_with_prio(tid, start, arg, stack_size,
                                      BH_THREAD_DEFAULT_PRIORITY);
}

korp_tid
os_self_thread()
{
    return (korp_tid)TlsGetValue(thread_data_key);
}

int
os_thread_join(korp_tid thread, void **p_retval)
{
    os_thread_data *thread_data, *curr_thread_data;

    /* Get thread data of current thread */
    curr_thread_data = thread_data_current();
    curr_thread_data->wait_node.next = NULL;

    /* Get thread data of thread to join */
    thread_data = (os_thread_data *)thread;
    bh_assert(thread_data);

    os_mutex_lock(&thread_data->wait_lock);

    if (thread_data->thread_exited) {
        /* Thread has exited */
        if (p_retval)
            *p_retval = thread_data->thread_retval;
        os_mutex_unlock(&thread_data->wait_lock);
        return BHT_OK;
    }

    /* Thread is running */
    if (!thread_data->thread_wait_list) { /* Waiting list is empty */
        thread_data->thread_wait_list = thread_data->thread_wait_list_end =
            &curr_thread_data->wait_node;
    }
    else { /* Waiting list isn't empty */
        /* Add to end of waiting list */
        thread_data->thread_wait_list_end->next = &curr_thread_data->wait_node;
        thread_data->thread_wait_list_end = &curr_thread_data->wait_node;
    }

    os_mutex_unlock(&thread_data->wait_lock);

    /* Wait the sem */
    os_sem_wait(&curr_thread_data->wait_node.sem);
    if (p_retval)
        *p_retval = curr_thread_data->wait_node.retval;
    return BHT_OK;
}

int
os_thread_detach(korp_tid thread)
{
    /* Do nothing */
    return BHT_OK;
    (void)thread;
}

void
os_thread_exit(void *retval)
{
    os_thread_cleanup(retval);
    _endthreadex(0);
}

int
os_thread_env_init()
{
    os_thread_data *thread_data = TlsGetValue(thread_data_key);

    if (thread_data)
        /* Already created */
        return BHT_OK;

    if (!(thread_data = BH_MALLOC(sizeof(os_thread_data))))
        return BHT_ERROR;

    memset(thread_data, 0, sizeof(os_thread_data));
    thread_data->thread_id = GetCurrentThreadId();

    if (os_sem_init(&thread_data->wait_node.sem) != BHT_OK)
        goto fail1;

    if (os_mutex_init(&thread_data->wait_lock) != BHT_OK)
        goto fail2;

    if (os_cond_init(&thread_data->wait_cond) != BHT_OK)
        goto fail3;

    if (!TlsSetValue(thread_data_key, thread_data))
        goto fail4;

    return BHT_OK;

fail4:
    os_cond_destroy(&thread_data->wait_cond);
fail3:
    os_mutex_destroy(&thread_data->wait_lock);
fail2:
    os_sem_destroy(&thread_data->wait_node.sem);
fail1:
    BH_FREE(thread_data);
    return BHT_ERROR;
}

void
os_thread_env_destroy()
{
    os_thread_data *thread_data = TlsGetValue(thread_data_key);

    /* Note that supervisor_thread_data's resources will be destroyed
       by os_thread_sys_destroy() */
    if (thread_data && thread_data != &supervisor_thread_data) {
        TlsSetValue(thread_data_key, NULL);
        os_cond_destroy(&thread_data->wait_cond);
        os_mutex_destroy(&thread_data->wait_lock);
        os_sem_destroy(&thread_data->wait_node.sem);
        BH_FREE(thread_data);
    }
}

bool
os_thread_env_inited()
{
    os_thread_data *thread_data = TlsGetValue(thread_data_key);
    return thread_data ? true : false;
}

int
os_sem_init(korp_sem *sem)
{
    bh_assert(sem);
    *sem = CreateSemaphore(NULL, 0, BH_SEM_COUNT_MAX, NULL);
    return (*sem != NULL) ? BHT_OK : BHT_ERROR;
}

int
os_sem_destroy(korp_sem *sem)
{
    bh_assert(sem);
    CloseHandle(*sem);
    return BHT_OK;
}

int
os_sem_wait(korp_sem *sem)
{
    DWORD ret;

    bh_assert(sem);

    ret = WaitForSingleObject(*sem, INFINITE);

    if (ret == WAIT_OBJECT_0)
        return BHT_OK;
    else if (ret == WAIT_TIMEOUT)
        return (int)WAIT_TIMEOUT;
    else /* WAIT_FAILED or others */
        return BHT_ERROR;
}

int
os_sem_reltimed_wait(korp_sem *sem, uint64 useconds)
{
    uint64 mseconds_64;
    DWORD ret, mseconds;

    bh_assert(sem);

    if (useconds == BHT_WAIT_FOREVER)
        mseconds = INFINITE;
    else {
        mseconds_64 = useconds / 1000;

        if (mseconds_64 < (uint64)(UINT32_MAX - 1)) {
            mseconds = (uint32)mseconds_64;
        }
        else {
            mseconds = UINT32_MAX - 1;
            os_printf("Warning: os_sem_reltimed_wait exceeds limit, "
                      "set to max timeout instead\n");
        }
    }

    ret = WaitForSingleObject(*sem, mseconds);

    if (ret == WAIT_OBJECT_0)
        return BHT_OK;
    else if (ret == WAIT_TIMEOUT)
        return (int)WAIT_TIMEOUT;
    else /* WAIT_FAILED or others */
        return BHT_ERROR;
}

int
os_sem_signal(korp_sem *sem)
{
    bh_assert(sem);
    return ReleaseSemaphore(*sem, 1, NULL) != FALSE ? BHT_OK : BHT_ERROR;
}

int
os_mutex_init(korp_mutex *mutex)
{
    bh_assert(mutex);
    *mutex = CreateMutex(NULL, FALSE, NULL);
    return (*mutex != NULL) ? BHT_OK : BHT_ERROR;
}

int
os_recursive_mutex_init(korp_mutex *mutex)
{
    bh_assert(mutex);
    *mutex = CreateMutex(NULL, FALSE, NULL);
    return (*mutex != NULL) ? BHT_OK : BHT_ERROR;
}

int
os_mutex_destroy(korp_mutex *mutex)
{
    assert(mutex);
    return CloseHandle(*mutex) ? BHT_OK : BHT_ERROR;
}

int
os_mutex_lock(korp_mutex *mutex)
{
    int ret;

    assert(mutex);

    if (*mutex == NULL) { /* static initializer? */
        HANDLE p = CreateMutex(NULL, FALSE, NULL);

        if (!p) {
            return BHT_ERROR;
        }

        if (InterlockedCompareExchangePointer((PVOID *)mutex, (PVOID)p, NULL)
            != NULL) {
            /* lock has been created by other threads */
            CloseHandle(p);
        }
    }

    ret = WaitForSingleObject(*mutex, INFINITE);
    return ret != WAIT_FAILED ? BHT_OK : BHT_ERROR;
}

int
os_mutex_unlock(korp_mutex *mutex)
{
    bh_assert(mutex);
    return ReleaseMutex(*mutex) ? BHT_OK : BHT_ERROR;
}

int
os_rwlock_init(korp_rwlock *lock)
{
    bh_assert(lock);

    InitializeSRWLock(&(lock->lock));
    lock->exclusive = false;

    return BHT_OK;
}

int
os_rwlock_rdlock(korp_rwlock *lock)
{
    bh_assert(lock);

    AcquireSRWLockShared(&(lock->lock));

    return BHT_OK;
}

int
os_rwlock_wrlock(korp_rwlock *lock)
{
    bh_assert(lock);

    AcquireSRWLockExclusive(&(lock->lock));
    lock->exclusive = true;

    return BHT_OK;
}

int
os_rwlock_unlock(korp_rwlock *lock)
{
    bh_assert(lock);

    if (lock->exclusive) {
        lock->exclusive = false;
        ReleaseSRWLockExclusive(&(lock->lock));
    }
    else {
        ReleaseSRWLockShared(&(lock->lock));
    }

    return BHT_OK;
}

int
os_rwlock_destroy(korp_rwlock *lock)
{
    (void)lock;

    return BHT_OK;
}

int
os_cond_init(korp_cond *cond)
{
    bh_assert(cond);
    if (os_mutex_init(&cond->wait_list_lock) != BHT_OK)
        return BHT_ERROR;

    cond->thread_wait_list = cond->thread_wait_list_end = NULL;
    return BHT_OK;
}

int
os_cond_destroy(korp_cond *cond)
{
    bh_assert(cond);
    os_mutex_destroy(&cond->wait_list_lock);
    return BHT_OK;
}

static int
os_cond_wait_internal(korp_cond *cond, korp_mutex *mutex, bool timed,
                      uint64 useconds)
{
    os_thread_wait_node *node = &thread_data_current()->wait_node;

    node->next = NULL;

    bh_assert(cond);
    bh_assert(mutex);
    os_mutex_lock(&cond->wait_list_lock);
    if (!cond->thread_wait_list) { /* Waiting list is empty */
        cond->thread_wait_list = cond->thread_wait_list_end = node;
    }
    else { /* Waiting list isn't empty */
        /* Add to end of wait list */
        cond->thread_wait_list_end->next = node;
        cond->thread_wait_list_end = node;
    }
    os_mutex_unlock(&cond->wait_list_lock);

    /* Unlock mutex, wait sem and lock mutex again */
    os_mutex_unlock(mutex);
    int wait_result;
    if (timed)
        wait_result = os_sem_reltimed_wait(&node->sem, useconds);
    else
        wait_result = os_sem_wait(&node->sem);
    os_mutex_lock(mutex);

    /* Remove wait node from wait list */
    os_mutex_lock(&cond->wait_list_lock);
    if (cond->thread_wait_list == node) {
        cond->thread_wait_list = node->next;

        if (cond->thread_wait_list_end == node) {
            bh_assert(node->next == NULL);
            cond->thread_wait_list_end = NULL;
        }
    }
    else {
        /* Remove from the wait list */
        os_thread_wait_node *p = cond->thread_wait_list;
        while (p->next != node)
            p = p->next;
        p->next = node->next;

        if (cond->thread_wait_list_end == node) {
            cond->thread_wait_list_end = p;
        }
    }
    os_mutex_unlock(&cond->wait_list_lock);

    return wait_result;
}

int
os_cond_wait(korp_cond *cond, korp_mutex *mutex)
{
    return os_cond_wait_internal(cond, mutex, false, 0);
}

int
os_cond_reltimedwait(korp_cond *cond, korp_mutex *mutex, uint64 useconds)
{
    if (useconds == BHT_WAIT_FOREVER) {
        return os_cond_wait_internal(cond, mutex, false, 0);
    }
    else {
        return os_cond_wait_internal(cond, mutex, true, useconds);
    }
}

int
os_cond_signal(korp_cond *cond)
{
    /* Signal the head wait node of wait list */
    os_mutex_lock(&cond->wait_list_lock);
    if (cond->thread_wait_list)
        os_sem_signal(&cond->thread_wait_list->sem);
    os_mutex_unlock(&cond->wait_list_lock);

    return BHT_OK;
}

int
os_cond_broadcast(korp_cond *cond)
{
    /* Signal all of the wait node of wait list */
    os_mutex_lock(&cond->wait_list_lock);
    if (cond->thread_wait_list) {
        os_thread_wait_node *p = cond->thread_wait_list;
        while (p) {
            os_sem_signal(&p->sem);
            p = p->next;
        }
    }

    os_mutex_unlock(&cond->wait_list_lock);

    return BHT_OK;
}

static os_thread_local_attribute uint8 *thread_stack_boundary = NULL;

static ULONG
GetCurrentThreadStackLimits_Win7(PULONG_PTR p_low_limit,
                                 PULONG_PTR p_high_limit)
{
    MEMORY_BASIC_INFORMATION mbi;
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();

    if (!tib) {
        os_printf("warning: NtCurrentTeb() failed\n");
        return -1;
    }

    *p_high_limit = (ULONG_PTR)tib->StackBase;

    if (VirtualQuery(tib->StackLimit, &mbi, sizeof(mbi))) {
        *p_low_limit = (ULONG_PTR)mbi.AllocationBase;
        return 0;
    }

    os_printf("warning: VirtualQuery() failed\n");
    return GetLastError();
}

uint8 *
os_thread_get_stack_boundary()
{
    ULONG_PTR low_limit = 0, high_limit = 0;
    uint32 page_size;

    if (thread_stack_boundary)
        return thread_stack_boundary;

    page_size = os_getpagesize();
    if (GetCurrentThreadStackLimits_Kernel32) {
        GetCurrentThreadStackLimits_Kernel32(&low_limit, &high_limit);
    }
    else {
        if (0 != GetCurrentThreadStackLimits_Win7(&low_limit, &high_limit))
            return NULL;
    }

    /* 4 pages are set unaccessible by system, we reserved
       one more page at least for safety */
    thread_stack_boundary = (uint8 *)(uintptr_t)low_limit + page_size * 5;
    return thread_stack_boundary;
}

void
os_thread_jit_write_protect_np(bool enabled)
{}

#ifdef OS_ENABLE_HW_BOUND_CHECK
static os_thread_local_attribute bool thread_signal_inited = false;

int
os_thread_signal_init()
{
#if WASM_DISABLE_STACK_HW_BOUND_CHECK == 0
    ULONG StackSizeInBytes = 16 * 1024;
#endif
    bool ret;

    if (thread_signal_inited)
        return 0;

#if WASM_DISABLE_STACK_HW_BOUND_CHECK == 0
    ret = SetThreadStackGuarantee(&StackSizeInBytes);
#else
    ret = true;
#endif
    if (ret)
        thread_signal_inited = true;
    return ret ? 0 : -1;
}

void
os_thread_signal_destroy()
{
    /* Do nothing */
}

bool
os_thread_signal_inited()
{
    return thread_signal_inited;
}
#endif
