/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-FileCopyrightText: 2024 Siemens AG (For Zephyr usermode changes)
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

/* clang-format off */
#define bh_assert(v) do {                                   \
    if (!(v)) {                                             \
        printf("\nASSERTION FAILED: %s, at %s, line %d\n",  \
               #v, __FILE__, __LINE__);                     \
        abort();                                            \
    }                                                       \
} while (0)
/* clang-format on */

#if defined(CONFIG_ARM_MPU) || defined(CONFIG_ARC_MPU) \
    || KERNEL_VERSION_NUMBER > 0x020300 /* version 2.3.0 */
#define BH_ENABLE_ZEPHYR_MPU_STACK 1
#elif !defined(BH_ENABLE_ZEPHYR_MPU_STACK)
#define BH_ENABLE_ZEPHYR_MPU_STACK 0
#endif
#if !defined(BH_ZEPHYR_MPU_STACK_SIZE)
#define BH_ZEPHYR_MPU_STACK_SIZE APP_THREAD_STACK_SIZE_MIN
#endif
#if !defined(BH_ZEPHYR_MPU_STACK_COUNT)
#define BH_ZEPHYR_MPU_STACK_COUNT 4
#endif

#if BH_ENABLE_ZEPHYR_MPU_STACK != 0
static K_THREAD_STACK_ARRAY_DEFINE(mpu_stacks, BH_ZEPHYR_MPU_STACK_COUNT,
                                   BH_ZEPHYR_MPU_STACK_SIZE);
static bool mpu_stack_allocated[BH_ZEPHYR_MPU_STACK_COUNT];
static mutex_t mpu_stack_lock;

static char *
mpu_stack_alloc()
{
    int i;

    mutex_lock(&mpu_stack_lock, K_FOREVER);
    for (i = 0; i < BH_ZEPHYR_MPU_STACK_COUNT; i++) {
        if (!mpu_stack_allocated[i]) {
            mpu_stack_allocated[i] = true;
            mutex_unlock(&mpu_stack_lock);
            return (char *)mpu_stacks[i];
        }
    }
    mutex_unlock(&mpu_stack_lock);
    return NULL;
}

static void
mpu_stack_free(char *stack)
{
    int i;

    mutex_lock(&mpu_stack_lock, K_FOREVER);
    for (i = 0; i < BH_ZEPHYR_MPU_STACK_COUNT; i++) {
        if ((char *)mpu_stacks[i] == stack)
            mpu_stack_allocated[i] = false;
    }
    mutex_unlock(&mpu_stack_lock);
}
#endif

typedef struct os_thread_wait_node {
    sem_t sem;
    os_thread_wait_list next;
} os_thread_wait_node;

typedef struct os_thread_data {
    /* Next thread data */
    struct os_thread_data *next;
    /* Zephyr thread handle */
    korp_tid tid;
    /* Jeff thread local root */
    void *tlr;
    /* Lock for waiting list */
    mutex_t wait_list_lock;
    /* Waiting list of other threads who are joining this thread */
    os_thread_wait_list thread_wait_list;
    /* Thread stack size */
    unsigned stack_size;
#if BH_ENABLE_ZEPHYR_MPU_STACK == 0
    /* Thread stack */
    char stack[1];
#else
    char *stack;
#endif
} os_thread_data;

typedef struct os_thread_obj {
    struct k_thread thread;
    /* Whether the thread is terminated and this thread object is to
     be freed in the future. */
    bool to_be_freed;
    struct os_thread_obj *next;
} os_thread_obj;

static bool is_thread_sys_inited = false;

/* Thread data of supervisor thread */
static os_thread_data supervisor_thread_data;

/* Lock for thread data list */
static mutex_t thread_data_lock;

/* Thread data list */
static os_thread_data *thread_data_list = NULL;

/* Lock for thread object list */
static mutex_t thread_obj_lock;

/* Thread object list */
static os_thread_obj *thread_obj_list = NULL;

static void
thread_data_list_add(os_thread_data *thread_data)
{
    mutex_lock(&thread_data_lock, K_FOREVER);
    if (!thread_data_list)
        thread_data_list = thread_data;
    else {
        /* If already in list, just return */
        os_thread_data *p = thread_data_list;
        while (p) {
            if (p == thread_data) {
                mutex_unlock(&thread_data_lock);
                return;
            }
            p = p->next;
        }

        /* Set as head of list */
        thread_data->next = thread_data_list;
        thread_data_list = thread_data;
    }
    mutex_unlock(&thread_data_lock);
}

static void
thread_data_list_remove(os_thread_data *thread_data)
{
    mutex_lock(&thread_data_lock, K_FOREVER);
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
    mutex_unlock(&thread_data_lock);
}

static os_thread_data *
thread_data_list_lookup(k_tid_t tid)
{
    mutex_lock(&thread_data_lock, K_FOREVER);
    if (thread_data_list) {
        os_thread_data *p = thread_data_list;
        while (p) {
            if (p->tid == tid) {
                /* Found */
                mutex_unlock(&thread_data_lock);
                return p;
            }
            p = p->next;
        }
    }
    mutex_unlock(&thread_data_lock);
    return NULL;
}

static void
thread_obj_list_add(os_thread_obj *thread_obj)
{
    mutex_lock(&thread_obj_lock, K_FOREVER);
    if (!thread_obj_list)
        thread_obj_list = thread_obj;
    else {
        /* Set as head of list */
        thread_obj->next = thread_obj_list;
        thread_obj_list = thread_obj;
    }
    mutex_unlock(&thread_obj_lock);
}

static void
thread_obj_list_reclaim()
{
    os_thread_obj *p, *p_prev;
    mutex_lock(&thread_obj_lock, K_FOREVER);
    p_prev = NULL;
    p = thread_obj_list;
    while (p) {
        if (p->to_be_freed) {
            if (p_prev == NULL) { /* p is the head of list */
                thread_obj_list = p->next;
                BH_FREE(p);
                p = thread_obj_list;
            }
            else { /* p is not the head of list */
                p_prev->next = p->next;
                BH_FREE(p);
                p = p_prev->next;
            }
        }
        else {
            p_prev = p;
            p = p->next;
        }
    }
    mutex_unlock(&thread_obj_lock);
}

int
os_thread_sys_init()
{
    if (is_thread_sys_inited)
        return BHT_OK;

#if BH_ENABLE_ZEPHYR_MPU_STACK != 0
    mutex_init(&mpu_stack_lock);
#endif
    mutex_init(&thread_data_lock);
    mutex_init(&thread_obj_lock);

    /* Initialize supervisor thread data */
    memset(&supervisor_thread_data, 0, sizeof(supervisor_thread_data));
    supervisor_thread_data.tid = k_current_get();
    /* Set as head of thread data list */
    thread_data_list = &supervisor_thread_data;

    is_thread_sys_inited = true;
    return BHT_OK;
}

void
os_thread_sys_destroy(void)
{
    if (is_thread_sys_inited) {
        is_thread_sys_inited = false;
    }
}

static os_thread_data *
thread_data_current()
{
    k_tid_t tid = k_current_get();
    return thread_data_list_lookup(tid);
}

static void
os_thread_cleanup(void)
{
    os_thread_data *thread_data = thread_data_current();

    bh_assert(thread_data != NULL);
    mutex_lock(&thread_data->wait_list_lock, K_FOREVER);
    if (thread_data->thread_wait_list) {
        /* Signal each joining thread */
        os_thread_wait_list head = thread_data->thread_wait_list;
        while (head) {
            os_thread_wait_list next = head->next;
            sem_give(&head->sem);
            /* head will be freed by joining thread */
            head = next;
        }
        thread_data->thread_wait_list = NULL;
    }
    mutex_unlock(&thread_data->wait_list_lock);

    thread_data_list_remove(thread_data);
    /* Set flag to true for the next thread creating to
     free the thread object */
    ((os_thread_obj *)thread_data->tid)->to_be_freed = true;
#if BH_ENABLE_ZEPHYR_MPU_STACK != 0
    mpu_stack_free(thread_data->stack);
#endif
    BH_FREE(thread_data);
}

static void
os_thread_wrapper(void *start, void *arg, void *thread_data)
{
    /* Set thread custom data */
    ((os_thread_data *)thread_data)->tid = k_current_get();
    thread_data_list_add(thread_data);

    ((thread_start_routine_t)start)(arg);
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
    korp_tid tid;
    os_thread_data *thread_data;
    unsigned thread_data_size;

    if (!p_tid || !stack_size)
        return BHT_ERROR;

    /* Free the thread objects of terminated threads */
    thread_obj_list_reclaim();

    /* Create and initialize thread object */
    if (!(tid = BH_MALLOC(sizeof(os_thread_obj))))
        return BHT_ERROR;

    memset(tid, 0, sizeof(os_thread_obj));

    /* Create and initialize thread data */
#if BH_ENABLE_ZEPHYR_MPU_STACK == 0
    if (stack_size < APP_THREAD_STACK_SIZE_MIN)
        stack_size = APP_THREAD_STACK_SIZE_MIN;
    thread_data_size = offsetof(os_thread_data, stack) + stack_size;
#else
    stack_size = BH_ZEPHYR_MPU_STACK_SIZE;
    thread_data_size = sizeof(os_thread_data);
#endif
    if (!(thread_data = BH_MALLOC(thread_data_size))) {
        goto fail1;
    }

    memset(thread_data, 0, thread_data_size);
    mutex_init(&thread_data->wait_list_lock);
    thread_data->stack_size = stack_size;
    thread_data->tid = tid;

#if BH_ENABLE_ZEPHYR_MPU_STACK != 0
    if (!(thread_data->stack = mpu_stack_alloc())) {
        goto fail2;
    }
#endif

    /* Create the thread */
    if (!((tid = k_thread_create(tid, (k_thread_stack_t *)thread_data->stack,
                                 stack_size, os_thread_wrapper, start, arg,
                                 thread_data, prio, 0, K_NO_WAIT)))) {
        goto fail3;
    }

    bh_assert(tid == thread_data->tid);

    k_thread_name_set(tid, "wasm-zephyr");

    /* Set thread custom data */
    thread_data_list_add(thread_data);
    thread_obj_list_add((os_thread_obj *)tid);
    *p_tid = tid;
    return BHT_OK;

fail3:
#if BH_ENABLE_ZEPHYR_MPU_STACK != 0
    mpu_stack_free(thread_data->stack);
fail2:
#endif
    BH_FREE(thread_data);
fail1:
    BH_FREE(tid);
    return BHT_ERROR;
}

korp_tid
os_self_thread()
{
    return (korp_tid)k_current_get();
}

int
os_thread_join(korp_tid thread, void **value_ptr)
{
    (void)value_ptr;
    os_thread_data *thread_data;
    os_thread_wait_node *node;

    /* Get thread data */
    thread_data = thread_data_list_lookup(thread);

    if (thread_data == NULL) {
        os_printf(
            "Can't join thread %p, probably already exited or does not exist",
            thread);
        return BHT_OK;
    }

    /* Create wait node and append it to wait list */
    if (!(node = BH_MALLOC(sizeof(os_thread_wait_node))))
        return BHT_ERROR;

    sem_init(&node->sem, 0, 1);
    node->next = NULL;

    mutex_lock(&thread_data->wait_list_lock, K_FOREVER);
    if (!thread_data->thread_wait_list)
        thread_data->thread_wait_list = node;
    else {
        /* Add to end of waiting list */
        os_thread_wait_node *p = thread_data->thread_wait_list;
        while (p->next)
            p = p->next;
        p->next = node;
    }
    mutex_unlock(&thread_data->wait_list_lock);

    /* Wait the sem */
    sem_take(&node->sem, K_FOREVER);

    /* Wait some time for the thread to be actually terminated */
    k_sleep(Z_TIMEOUT_MS(100));

    /* Destroy resource */
    BH_FREE(node);
    return BHT_OK;
}

int
os_mutex_init(korp_mutex *mutex)
{
    mutex_init(mutex);
    return BHT_OK;
}

int
os_recursive_mutex_init(korp_mutex *mutex)
{
    mutex_init(mutex);
    return BHT_OK;
}

int
os_mutex_destroy(korp_mutex *mutex)
{
    (void)mutex;
    return BHT_OK;
}

int
os_mutex_lock(korp_mutex *mutex)
{
    return mutex_lock(mutex, K_FOREVER);
}

int
os_mutex_unlock(korp_mutex *mutex)
{
#if KERNEL_VERSION_NUMBER >= 0x020200 /* version 2.2.0 */
    return mutex_unlock(mutex);
#else
    mutex_unlock(mutex);
    return 0;
#endif
}

int
os_cond_init(korp_cond *cond)
{
    mutex_init(&cond->wait_list_lock);
    cond->thread_wait_list = NULL;
    return BHT_OK;
}

int
os_cond_destroy(korp_cond *cond)
{
    (void)cond;
    return BHT_OK;
}

static int
os_cond_wait_internal(korp_cond *cond, korp_mutex *mutex, bool timed, int mills)
{
    os_thread_wait_node *node;

    /* Create wait node and append it to wait list */
    if (!(node = BH_MALLOC(sizeof(os_thread_wait_node))))
        return BHT_ERROR;

    sem_init(&node->sem, 0, 1);
    node->next = NULL;

    mutex_lock(&cond->wait_list_lock, K_FOREVER);
    if (!cond->thread_wait_list)
        cond->thread_wait_list = node;
    else {
        /* Add to end of wait list */
        os_thread_wait_node *p = cond->thread_wait_list;
        while (p->next)
            p = p->next;
        p->next = node;
    }
    mutex_unlock(&cond->wait_list_lock);

    /* Unlock mutex, wait sem and lock mutex again */
    mutex_unlock(mutex);
    sem_take(&node->sem, timed ? Z_TIMEOUT_MS(mills) : K_FOREVER);
    mutex_lock(mutex, K_FOREVER);

    /* Remove wait node from wait list */
    mutex_lock(&cond->wait_list_lock, K_FOREVER);
    if (cond->thread_wait_list == node)
        cond->thread_wait_list = node->next;
    else {
        /* Remove from the wait list */
        os_thread_wait_node *p = cond->thread_wait_list;
        while (p->next != node)
            p = p->next;
        p->next = node->next;
    }
    BH_FREE(node);
    mutex_unlock(&cond->wait_list_lock);

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
        int32 mills;

        if (mills_64 < (uint64)INT32_MAX) {
            mills = (int32)mills_64;
        }
        else {
            mills = INT32_MAX;
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
    mutex_lock(&cond->wait_list_lock, K_FOREVER);
    if (cond->thread_wait_list)
        sem_give(&cond->thread_wait_list->sem);
    mutex_unlock(&cond->wait_list_lock);

    return BHT_OK;
}

uint8 *
os_thread_get_stack_boundary()
{
#if defined(CONFIG_THREAD_STACK_INFO) && !defined(CONFIG_USERSPACE)
    korp_tid thread = k_current_get();
    return (uint8 *)thread->stack_info.start;
#else
    return NULL;
#endif
}

void
os_thread_jit_write_protect_np(bool enabled)
{}

int
os_thread_detach(korp_tid thread)
{
    (void)thread;
    return BHT_OK;
}

void
os_thread_exit(void *retval)
{
    (void)retval;
    os_thread_cleanup();
    k_thread_abort(k_current_get());
}

int
os_cond_broadcast(korp_cond *cond)
{
    os_thread_wait_node *node;
    mutex_lock(&cond->wait_list_lock, K_FOREVER);
    node = cond->thread_wait_list;
    while (node) {
        os_thread_wait_node *next = node->next;
        sem_give(&node->sem);
        node = next;
    }
    mutex_unlock(&cond->wait_list_lock);
    return BHT_OK;
}
