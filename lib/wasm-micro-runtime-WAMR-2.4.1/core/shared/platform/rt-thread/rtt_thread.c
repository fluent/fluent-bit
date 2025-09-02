/*
 * Copyright 2024 Sony Semiconductor Solutions Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdint.h>

struct os_thread_data;
typedef struct os_thread_wait_node *os_thread_wait_list;
typedef struct os_thread_wait_node {
    /* Binary semaphore */
    rt_sem_t sem;
    os_thread_wait_list next;
} os_thread_wait_node;

typedef struct os_thread_data {
    /* Next thread data */
    struct os_thread_data *next;
    /* Thread handle */
    rt_thread_t handle;
    /* Thread start routine */
    thread_start_routine_t start_routine;
    /* Thread start routine argument */
    void *arg;
    /* Wait node of current thread */
    os_thread_wait_node wait_node;
    /* Lock for waiting list */
    rt_mutex_t wait_list_lock;
    /* Waiting list of other threads who are joining this thread */
    os_thread_wait_list thread_wait_list;
} os_thread_data;

/* Lock for thread data list */
static rt_mutex_t thread_data_lock;

static bool is_thread_sys_inited = false;

/* Thread data list */
static os_thread_data *thread_data_list = NULL;

/* Thread data of supervisor thread */
static os_thread_data supervisor_thread_data;

/* Thread name index */
static int thread_name_index = 0;

static void
thread_data_list_add(os_thread_data *thread_data)
{
    rt_mutex_take(thread_data_lock, RT_WAITING_FOREVER);
    if (!thread_data_list)
        thread_data_list = thread_data;
    else {
        /* If already in list, just return */
        os_thread_data *p = thread_data_list;
        while (p) {
            if (p == thread_data) {
                rt_mutex_release(thread_data_lock);
                return;
            }
            p = p->next;
        }

        /* Set as head of list */
        thread_data->next = thread_data_list;
        thread_data_list = thread_data;
    }
    rt_mutex_release(thread_data_lock);
}

static void
os_thread_wrapper(void *arg)
{
    os_thread_data *thread_data = arg;

    thread_data->handle = rt_thread_self();
    thread_data_list_add(thread_data);

    thread_data->start_routine(thread_data->arg);
    rt_kprintf("start_routine quit\n");
    os_thread_exit(NULL);
}

static void
thread_data_list_remove(os_thread_data *thread_data)
{
    rt_mutex_take(thread_data_lock, RT_WAITING_FOREVER);
    if (thread_data_list) {
        if (thread_data_list == thread_data)
            thread_data_list = thread_data_list->next;
        else {
            /* Search and remove it from list */
            os_thread_data *p = thread_data_list;
            while (p && p->next != thread_data)
                p = p->next;
            if (p && p->next == thread_data)
                p->next = p->next->next;
        }
    }
    rt_mutex_release(thread_data_lock);
}

static os_thread_data *
thread_data_list_lookup(rt_thread_t handle)
{
    rt_mutex_take(thread_data_lock, RT_WAITING_FOREVER);
    if (thread_data_list) {
        os_thread_data *p = thread_data_list;
        while (p) {
            if (p->handle == handle) {
                /* Found */
                rt_mutex_release(thread_data_lock);
                return p;
            }
            p = p->next;
        }
    }
    rt_mutex_release(thread_data_lock);
    return NULL;
}

static os_thread_data *
thread_data_current()
{
    rt_thread_t handle = rt_thread_self();
    return thread_data_list_lookup(handle);
}

int
os_thread_sys_init()
{
    if (is_thread_sys_inited)
        return BHT_OK;

    if (!(thread_data_lock =
              rt_mutex_create("thread_data_lock_mutex", RT_IPC_FLAG_FIFO)))
        return BHT_ERROR;

    /* Initialize supervisor thread data */
    memset(&supervisor_thread_data, 0, sizeof(supervisor_thread_data));

    if (!(supervisor_thread_data.wait_node.sem =
              rt_sem_create("spvr", 0, RT_IPC_FLAG_PRIO))) {
        rt_mutex_delete(thread_data_lock);
        return BHT_ERROR;
    }

    supervisor_thread_data.handle = rt_thread_self();
    /* Set as head of thread data list */
    thread_data_list = &supervisor_thread_data;

    is_thread_sys_inited = true;
    return BHT_OK;
}

void
os_thread_sys_destroy()
{
    if (is_thread_sys_inited) {
        rt_sem_release(supervisor_thread_data.wait_node.sem);
        rt_mutex_delete(thread_data_lock);
        is_thread_sys_inited = false;
    }
}

korp_tid
os_self_thread(void)
{
    return rt_thread_self();
}

uint8 *
os_thread_get_stack_boundary(void)
{
    rt_thread_t tid = rt_thread_self();
    return tid->stack_addr;
}

void
os_thread_jit_write_protect_np(bool enabled)
{}

int
os_mutex_init(korp_mutex *mutex)
{
    return rt_mutex_init(mutex, "wamr0", RT_IPC_FLAG_FIFO);
}

int
os_mutex_destroy(korp_mutex *mutex)
{
    return rt_mutex_detach(mutex);
}

int
os_mutex_lock(korp_mutex *mutex)
{
    return rt_mutex_take(mutex, RT_WAITING_FOREVER);
}

int
os_mutex_unlock(korp_mutex *mutex)
{
    return rt_mutex_release(mutex);
}

/*
 * functions below was not implement
 */

int
os_cond_init(korp_cond *cond)
{
    return 0;
}

int
os_cond_destroy(korp_cond *cond)
{
    return 0;
}

int
os_cond_wait(korp_cond *cond, korp_mutex *mutex)
{
    return 0;
}

int
os_cond_signal(korp_cond *cond)
{
    return 0;
}

int
os_cond_reltimedwait(korp_cond *cond, korp_mutex *mutex, uint64 useconds)
{
    return 0;
}

int
os_rwlock_init(korp_rwlock *lock)
{
    return BHT_OK;
}

int
os_rwlock_rdlock(korp_rwlock *lock)
{

    return BHT_OK;
}

int
os_rwlock_wrlock(korp_rwlock *lock)
{

    return BHT_OK;
}

int
os_rwlock_unlock(korp_rwlock *lock)
{
    return BHT_OK;
}

int
os_rwlock_destroy(korp_rwlock *lock)
{
    return BHT_OK;
}

int
os_thread_create_with_prio(korp_tid *p_tid, thread_start_routine_t start,
                           void *arg, unsigned int stack_size, int prio)
{
    os_thread_data *thread_data;
    char thread_name[32];
    void *stack;

    if (!p_tid || !stack_size)
        return BHT_ERROR;

    /* Create and initialize thread data */
    if (!(thread_data = rt_malloc(sizeof(os_thread_data))))
        return BHT_ERROR;

    memset(thread_data, 0, sizeof(os_thread_data));

    thread_data->start_routine = start;
    thread_data->arg = arg;

    if (!(thread_data->wait_node.sem =
              rt_sem_create("sem", 0, RT_IPC_FLAG_PRIO)))
        goto fail1;

    if (!(thread_data->wait_list_lock =
              rt_mutex_create("wait_list_lock_mutex", RT_IPC_FLAG_FIFO)))
        goto fail2;

    snprintf(thread_name, sizeof(thread_name), "%s%d", "wasm-thread-",
             ++thread_name_index);

    thread_data->handle = rt_thread_create(thread_name, os_thread_wrapper,
                                           thread_data, stack_size, 15, 5);
    if (thread_data->handle == RT_NULL) {
        rt_kprintf("os_thread_create_with_prio failed, tid=%d\n",
                   thread_data->handle);
        goto fail3;
    }

    thread_data_list_add(thread_data);
    *p_tid = thread_data->handle;
    rt_thread_startup(*p_tid);
    return BHT_OK;

fail3:
    rt_mutex_delete(thread_data->wait_list_lock);
fail2:
    rt_sem_delete(thread_data->wait_node.sem);
fail1:
    rt_free(thread_data);
    return BHT_ERROR;
}

int
os_thread_create(korp_tid *p_tid, thread_start_routine_t start, void *arg,
                 unsigned int stack_size)
{
    return os_thread_create_with_prio(p_tid, start, arg, stack_size,
                                      BH_THREAD_DEFAULT_PRIORITY);
}

int
os_thread_detach(korp_tid thread)
{
    /* Do nothing */
    (void)thread;
    return BHT_OK;
}

int
os_thread_join(korp_tid thread, void **value_ptr)
{
    os_thread_data *thread_data, *curr_thread_data;
    rt_thread_t handle = thread;

    (void)value_ptr;

    /* Get thread data of current thread */
    curr_thread_data = thread_data_current();
    curr_thread_data->wait_node.next = NULL;

    /* Get thread data */
    thread_data = thread_data_list_lookup(handle);

    rt_mutex_take(thread_data->wait_list_lock, RT_WAITING_FOREVER);
    if (!thread_data->thread_wait_list)
        thread_data->thread_wait_list = &curr_thread_data->wait_node;
    else {
        /* Add to end of waiting list */
        os_thread_wait_node *p = thread_data->thread_wait_list;
        while (p->next)
            p = p->next;
        p->next = &curr_thread_data->wait_node;
    }
    rt_mutex_release(thread_data->wait_list_lock);

    /* Wait the sem */
    rt_sem_take(curr_thread_data->wait_node.sem, RT_WAITING_FOREVER);
    return BHT_OK;
}

static void
os_thread_cleanup(void)
{
    os_thread_data *thread_data = thread_data_current();
    os_thread_wait_list thread_wait_list;
    rt_mutex_t wait_list_lock;
    rt_sem_t wait_node_sem;

    // bh_assert(thread_data != NULL);
    wait_list_lock = thread_data->wait_list_lock;
    thread_wait_list = thread_data->thread_wait_list;
    wait_node_sem = thread_data->wait_node.sem;

    rt_mutex_take(wait_list_lock, RT_WAITING_FOREVER);
    if (thread_wait_list) {
        /* Signal each joining thread */
        os_thread_wait_list head = thread_wait_list;
        while (head) {
            os_thread_wait_list next = head->next;
            rt_sem_release(head->sem);
            head = next;
        }
    }
    rt_mutex_release(wait_list_lock);

    /* Free sem and lock */
    rt_sem_delete(wait_node_sem);
    rt_mutex_delete(wait_list_lock);

    thread_data_list_remove(thread_data);
    rt_free(thread_data);
}

void
os_thread_exit(void *retval)
{
    (void)retval;
    os_thread_cleanup();
    // vTaskDelete(NULL);
}

int
os_thread_kill(korp_tid tid, int sig)
{
    return rt_thread_kill(tid, sig);
}
