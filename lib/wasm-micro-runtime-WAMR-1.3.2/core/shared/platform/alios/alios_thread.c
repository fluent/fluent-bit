/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

/* clang-format off */
#define bh_assert(v) do {                                   \
    if (!(v)) {                                             \
        printf("\nASSERTION FAILED: %s, at %s, line %d\n",  \
               #v, __FILE__, __LINE__);                     \
        aos_reboot();                                       \
        while (1);                                          \
    }                                                       \
} while (0)
/* clang-format on */

struct os_thread_data;
typedef struct os_thread_wait_node {
    aos_sem_t sem;
    os_thread_wait_list next;
} os_thread_wait_node;

typedef struct os_thread_data {
    /* Thread body */
    aos_task_t thread;
    /* Thread start routine */
    thread_start_routine_t start_routine;
    /* Thread start routine argument */
    void *arg;
    /* Thread local root */
    void *tlr;
    /* Wait node of current thread */
    os_thread_wait_node wait_node;
    /* Lock for waiting list */
    aos_mutex_t wait_list_lock;
    /* Waiting list of other threads who are joining this thread */
    os_thread_wait_list thread_wait_list;
} os_thread_data;

static bool is_thread_sys_inited = false;

/* Thread data of supervisor thread */
static os_thread_data supervisor_thread_data;

/* Thread data key */
static aos_task_key_t thread_data_key;

/* Thread name index */
static int thread_name_index;

int
os_thread_sys_init()
{
    if (is_thread_sys_inited)
        return BHT_OK;

    if (aos_task_key_create(&thread_data_key) != 0)
        return BHT_ERROR;

    /* Initialize supervisor thread data */
    memset(&supervisor_thread_data, 0, sizeof(supervisor_thread_data));

    if (aos_sem_new(&supervisor_thread_data.wait_node.sem, 1) != 0) {
        aos_task_key_delete(thread_data_key);
        return BHT_ERROR;
    }

    if (aos_task_setspecific(thread_data_key, &supervisor_thread_data)) {
        aos_sem_free(&supervisor_thread_data.wait_node.sem);
        aos_task_key_delete(thread_data_key);
        return BHT_ERROR;
    }

    is_thread_sys_inited = true;
    return BHT_OK;
}

void
os_thread_sys_destroy()
{
    if (is_thread_sys_inited) {
        aos_task_key_delete(thread_data_key);
        aos_sem_free(&supervisor_thread_data.wait_node.sem);
        is_thread_sys_inited = false;
    }
}

static os_thread_data *
thread_data_current()
{
    return aos_task_getspecific(thread_data_key);
}

static void
os_thread_cleanup(void)
{
    os_thread_data *thread_data = thread_data_current();
    os_thread_wait_list thread_wait_list;
    aos_mutex_t *wait_list_lock;
    aos_sem_t *wait_node_sem;

    bh_assert(thread_data != NULL);
    wait_list_lock = &thread_data->wait_list_lock;
    thread_wait_list = thread_data->thread_wait_list;
    wait_node_sem = &thread_data->wait_node.sem;

    /* Free thread data firstly */
    BH_FREE(thread_data);

    aos_mutex_lock(wait_list_lock, AOS_WAIT_FOREVER);
    if (thread_wait_list) {
        /* Signal each joining thread */
        os_thread_wait_list head = thread_wait_list;
        while (head) {
            os_thread_wait_list next = head->next;
            aos_sem_signal(&head->sem);
            head = next;
        }
    }
    aos_mutex_unlock(wait_list_lock);

    /* Free sem and lock */
    aos_sem_free(wait_node_sem);
    aos_mutex_free(wait_list_lock);
}

static void
os_thread_wrapper(void *arg)
{
    os_thread_data *thread_data = arg;

    /* Set thread custom data */
    if (!aos_task_setspecific(thread_data_key, thread_data))
        thread_data->start_routine(thread_data->arg);

    os_thread_cleanup();
}

int
os_thread_create(korp_tid *p_tid, thread_start_routine_t start, void *arg,
                 unsigned int stack_size)
{
    return os_thread_create_with_prio(p_tid, start, arg, stack_size,
                                      BH_THREAD_DEFAULT_PRIORITY);
}

int
os_thread_create_with_prio(korp_tid *p_tid, thread_start_routine_t start,
                           void *arg, unsigned int stack_size, int prio)
{
    os_thread_data *thread_data;
    char thread_name[32];

    if (!p_tid || !stack_size)
        return BHT_ERROR;

    /* Create and initialize thread data */
    if (!(thread_data = BH_MALLOC(sizeof(os_thread_data))))
        return BHT_ERROR;

    memset(thread_data, 0, sizeof(os_thread_data));

    thread_data->start_routine = start;
    thread_data->arg = arg;

    if (aos_sem_new(&thread_data->wait_node.sem, 1) != 0)
        goto fail1;

    if (aos_mutex_new(&thread_data->wait_list_lock))
        goto fail2;

    snprintf(thread_name, sizeof(thread_name), "%s%d", "wasm-thread-",
             ++thread_name_index);

    /* Create the thread */
    if (aos_task_new_ext((aos_task_t *)thread_data, thread_name,
                         os_thread_wrapper, thread_data, stack_size, prio))
        goto fail3;

    aos_msleep(10);
    *p_tid = (korp_tid)thread_data;
    return BHT_OK;

fail3:
    aos_mutex_free(&thread_data->wait_list_lock);
fail2:
    aos_sem_free(&thread_data->wait_node.sem);
fail1:
    BH_FREE(thread_data);
    return BHT_ERROR;
}

korp_tid
os_self_thread()
{
    return (korp_tid)aos_task_getspecific(thread_data_key);
}

int
os_thread_join(korp_tid thread, void **value_ptr)
{
    (void)value_ptr;
    os_thread_data *thread_data, *curr_thread_data;

    /* Get thread data of current thread */
    curr_thread_data = thread_data_current();
    curr_thread_data->wait_node.next = NULL;

    /* Get thread data */
    thread_data = (os_thread_data *)thread;

    aos_mutex_lock(&thread_data->wait_list_lock, AOS_WAIT_FOREVER);
    if (!thread_data->thread_wait_list)
        thread_data->thread_wait_list = &curr_thread_data->wait_node;
    else {
        /* Add to end of waiting list */
        os_thread_wait_node *p = thread_data->thread_wait_list;
        while (p->next)
            p = p->next;
        p->next = &curr_thread_data->wait_node;
    }
    aos_mutex_unlock(&thread_data->wait_list_lock);

    /* Wait the sem */
    aos_sem_wait(&curr_thread_data->wait_node.sem, AOS_WAIT_FOREVER);

    return BHT_OK;
}

int
os_mutex_init(korp_mutex *mutex)
{
    return aos_mutex_new(mutex) == 0 ? BHT_OK : BHT_ERROR;
}

int
os_mutex_destroy(korp_mutex *mutex)
{
    aos_mutex_free(mutex);
    return BHT_OK;
}

int
os_mutex_lock(korp_mutex *mutex)
{
    return aos_mutex_lock(mutex, AOS_WAIT_FOREVER);
}

int
os_mutex_unlock(korp_mutex *mutex)
{
    return aos_mutex_unlock(mutex);
}

int
os_cond_init(korp_cond *cond)
{
    if (aos_mutex_new(&cond->wait_list_lock) != 0)
        return BHT_ERROR;

    cond->thread_wait_list = NULL;
    return BHT_OK;
}

int
os_cond_destroy(korp_cond *cond)
{
    aos_mutex_free(&cond->wait_list_lock);
    return BHT_OK;
}

static int
os_cond_wait_internal(korp_cond *cond, korp_mutex *mutex, bool timed,
                      uint32 mills)
{
    os_thread_wait_node *node = &thread_data_current()->wait_node;

    node->next = NULL;

    aos_mutex_lock(&cond->wait_list_lock, AOS_WAIT_FOREVER);
    if (!cond->thread_wait_list)
        cond->thread_wait_list = node;
    else {
        /* Add to end of wait list */
        os_thread_wait_node *p = cond->thread_wait_list;
        while (p->next)
            p = p->next;
        p->next = node;
    }
    aos_mutex_unlock(&cond->wait_list_lock);

    /* Unlock mutex, wait sem and lock mutex again */
    aos_mutex_unlock(mutex);
    aos_sem_wait(&node->sem, timed ? mills : AOS_WAIT_FOREVER);
    aos_mutex_lock(mutex, AOS_WAIT_FOREVER);

    /* Remove wait node from wait list */
    aos_mutex_lock(&cond->wait_list_lock, AOS_WAIT_FOREVER);
    if (cond->thread_wait_list == node)
        cond->thread_wait_list = node->next;
    else {
        /* Remove from the wait list */
        os_thread_wait_node *p = cond->thread_wait_list;
        while (p->next != node)
            p = p->next;
        p->next = node->next;
    }
    aos_mutex_unlock(&cond->wait_list_lock);

    return BHT_OK;
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
        uint64 mills_64 = useconds / 1000;
        uint32 mills;

        if (mills_64 < (uint64)(UINT32_MAX - 1)) {
            mills = (uint64)mills_64;
        }
        else {
            mills = UINT32_MAX - 1;
            os_printf("Warning: os_cond_reltimedwait exceeds limit, "
                      "set to max timeout instead\n");
        }
        return os_cond_wait_internal(cond, mutex, true, mills);
    }
}

int
os_cond_signal(korp_cond *cond)
{
    /* Signal the head wait node of wait list */
    aos_mutex_lock(&cond->wait_list_lock, AOS_WAIT_FOREVER);
    if (cond->thread_wait_list)
        aos_sem_signal(&cond->thread_wait_list->sem);
    aos_mutex_unlock(&cond->wait_list_lock);

    return BHT_OK;
}

uint8 *
os_thread_get_stack_boundary()
{
    /* TODO: get alios stack boundary */
    return NULL;
}

void
os_thread_jit_write_protect_np(bool enabled)
{}