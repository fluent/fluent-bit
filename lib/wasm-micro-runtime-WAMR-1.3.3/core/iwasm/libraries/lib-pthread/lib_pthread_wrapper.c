/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_common.h"
#include "bh_log.h"
#include "wasm_export.h"
#include "../interpreter/wasm.h"
#include "../common/wasm_runtime_common.h"
#include "thread_manager.h"

#if WASM_ENABLE_INTERP != 0
#include "wasm_runtime.h"
#endif

#if WASM_ENABLE_AOT != 0
#include "aot_runtime.h"
#endif

#define WAMR_PTHREAD_KEYS_MAX 32

/* clang-format off */
#define get_module(exec_env) \
    wasm_exec_env_get_module(exec_env)

#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define get_thread_arg(exec_env) \
    wasm_exec_env_get_thread_arg(exec_env)

#define get_wasi_ctx(module_inst) \
    wasm_runtime_get_wasi_ctx(module_inst)

#define validate_app_addr(offset, size) \
    wasm_runtime_validate_app_addr(module_inst, offset, size)

#define validate_native_addr(addr, size) \
    wasm_runtime_validate_native_addr(module_inst, addr, size)

#define addr_app_to_native(offset) \
    wasm_runtime_addr_app_to_native(module_inst, offset)

#define addr_native_to_app(ptr) \
    wasm_runtime_addr_native_to_app(module_inst, ptr)
/* clang-format on */

enum {
    T_THREAD,
    T_MUTEX,
    T_COND,
    T_SEM,
};

enum thread_status_t {
    THREAD_INIT,
    THREAD_RUNNING,
    THREAD_CANCELLED,
    THREAD_EXIT,
};

enum mutex_status_t {
    MUTEX_CREATED,
    MUTEX_DESTROYED,
};

enum cond_status_t {
    COND_CREATED,
    COND_DESTROYED,
};

enum sem_status_t {
    SEM_CREATED,
    SEM_CLOSED,
    SEM_DESTROYED,
};

typedef struct ThreadKeyValueNode {
    bh_list_link l;
    wasm_exec_env_t exec_env;
    int32 thread_key_values[WAMR_PTHREAD_KEYS_MAX];
} ThreadKeyValueNode;

typedef struct KeyData {
    int32 destructor_func;
    bool is_created;
} KeyData;

typedef struct ClusterInfoNode {
    bh_list_link l;
    WASMCluster *cluster;
    HashMap *thread_info_map;
    /* Key data list */
    KeyData key_data_list[WAMR_PTHREAD_KEYS_MAX];
    korp_mutex key_data_list_lock;
    /* Every node contains the key value list for a thread */
    bh_list thread_list_head;
    bh_list *thread_list;
} ClusterInfoNode;

typedef struct ThreadInfoNode {
    wasm_exec_env_t parent_exec_env;
    wasm_exec_env_t exec_env;
    /* the id returned to app */
    uint32 handle;
    /* type can be [THREAD | MUTEX | CONDITION] */
    uint32 type;
    /* Thread status, this variable should be volatile
       as its value may be changed in different threads */
    volatile uint32 status;
    bool joinable;
    union {
        korp_tid thread;
        korp_mutex *mutex;
        korp_cond *cond;
#if WASM_ENABLE_LIB_PTHREAD_SEMAPHORE != 0
        korp_sem *sem;
#endif
        /* A copy of the thread return value */
        void *ret;
    } u;
} ThreadInfoNode;

typedef struct {
    ThreadInfoNode *info_node;
    /* table elem index of the app's entry function */
    uint32 elem_index;
    /* arg of the app's entry function */
    uint32 arg;
    wasm_module_inst_t module_inst;
} ThreadRoutineArgs;

typedef struct {
    uint32 handle;
    ThreadInfoNode *node;
} SemCallbackArgs;

static bh_list cluster_info_list;
#if WASM_ENABLE_LIB_PTHREAD_SEMAPHORE != 0
static HashMap *sem_info_map;
#endif
static korp_mutex thread_global_lock;
static uint32 handle_id = 1;

static void
lib_pthread_destroy_callback(WASMCluster *cluster);

static uint32
thread_handle_hash(void *handle)
{
    return (uint32)(uintptr_t)handle;
}

static bool
thread_handle_equal(void *h1, void *h2)
{
    return (uint32)(uintptr_t)h1 == (uint32)(uintptr_t)h2 ? true : false;
}

static void
thread_info_destroy(void *node)
{
    ThreadInfoNode *info_node = (ThreadInfoNode *)node;

    os_mutex_lock(&thread_global_lock);
    if (info_node->type == T_MUTEX) {
        if (info_node->status != MUTEX_DESTROYED)
            os_mutex_destroy(info_node->u.mutex);
        wasm_runtime_free(info_node->u.mutex);
    }
    else if (info_node->type == T_COND) {
        if (info_node->status != COND_DESTROYED)
            os_cond_destroy(info_node->u.cond);
        wasm_runtime_free(info_node->u.cond);
    }
#if WASM_ENABLE_LIB_PTHREAD_SEMAPHORE != 0
    else if (info_node->type == T_SEM) {
        if (info_node->status != SEM_DESTROYED)
            os_sem_close(info_node->u.sem);
    }
#endif
    wasm_runtime_free(info_node);
    os_mutex_unlock(&thread_global_lock);
}

bool
lib_pthread_init()
{
    if (0 != os_mutex_init(&thread_global_lock))
        return false;
    bh_list_init(&cluster_info_list);
    if (!wasm_cluster_register_destroy_callback(lib_pthread_destroy_callback)) {
        os_mutex_destroy(&thread_global_lock);
        return false;
    }
#if WASM_ENABLE_LIB_PTHREAD_SEMAPHORE != 0
    if (!(sem_info_map = bh_hash_map_create(
              32, true, (HashFunc)wasm_string_hash,
              (KeyEqualFunc)wasm_string_equal, NULL, thread_info_destroy))) {
        os_mutex_destroy(&thread_global_lock);
        return false;
    }
#endif
    return true;
}

void
lib_pthread_destroy()
{
#if WASM_ENABLE_LIB_PTHREAD_SEMAPHORE != 0
    bh_hash_map_destroy(sem_info_map);
#endif
    os_mutex_destroy(&thread_global_lock);
}

static ClusterInfoNode *
get_cluster_info(WASMCluster *cluster)
{
    ClusterInfoNode *node;

    os_mutex_lock(&thread_global_lock);
    node = bh_list_first_elem(&cluster_info_list);

    while (node) {
        if (cluster == node->cluster) {
            os_mutex_unlock(&thread_global_lock);
            return node;
        }
        node = bh_list_elem_next(node);
    }
    os_mutex_unlock(&thread_global_lock);

    return NULL;
}

static KeyData *
key_data_list_lookup(wasm_exec_env_t exec_env, int32 key)
{
    ClusterInfoNode *node;
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);

    if ((node = get_cluster_info(cluster))) {
        return (key >= 0 && key < WAMR_PTHREAD_KEYS_MAX
                && node->key_data_list[key].is_created)
                   ? &(node->key_data_list[key])
                   : NULL;
    }

    return NULL;
}

/**
 * Lookup the thread key value node for a thread, create a new one if failed
 * This design will reduce the memory usage. If the thread doesn't use the
 * local storage, it will not occupy memory space.
 */
static int32 *
key_value_list_lookup_or_create(wasm_exec_env_t exec_env, ClusterInfoNode *info,
                                int32 key)
{
    KeyData *key_node;
    ThreadKeyValueNode *data;

    /* Check if the key is valid */
    key_node = key_data_list_lookup(exec_env, key);
    if (!key_node) {
        return NULL;
    }

    /* Find key values node */
    data = bh_list_first_elem(info->thread_list);
    while (data) {
        if (data->exec_env == exec_env)
            return data->thread_key_values;
        data = bh_list_elem_next(data);
    }

    /* If not found, create a new node for this thread */
    if (!(data = wasm_runtime_malloc(sizeof(ThreadKeyValueNode))))
        return NULL;
    memset(data, 0, sizeof(ThreadKeyValueNode));
    data->exec_env = exec_env;

    if (bh_list_insert(info->thread_list, data) != 0) {
        wasm_runtime_free(data);
        return NULL;
    }

    return data->thread_key_values;
}

static void
call_key_destructor(wasm_exec_env_t exec_env)
{
    int32 i;
    uint32 destructor_index;
    KeyData *key_node;
    ThreadKeyValueNode *value_node;
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    ClusterInfoNode *info = get_cluster_info(cluster);

    if (!info) {
        return;
    }

    value_node = bh_list_first_elem(info->thread_list);
    while (value_node) {
        if (value_node->exec_env == exec_env)
            break;
        value_node = bh_list_elem_next(value_node);
    }

    /* This thread hasn't created key value node */
    if (!value_node)
        return;

    /* Destroy key values */
    for (i = 0; i < WAMR_PTHREAD_KEYS_MAX; i++) {
        if (value_node->thread_key_values[i] != 0) {
            int32 value = value_node->thread_key_values[i];
            os_mutex_lock(&info->key_data_list_lock);

            if ((key_node = key_data_list_lookup(exec_env, i)))
                destructor_index = key_node->destructor_func;
            else
                destructor_index = 0;
            os_mutex_unlock(&info->key_data_list_lock);

            /* reset key value */
            value_node->thread_key_values[i] = 0;

            /* Call the destructor func provided by app */
            if (destructor_index) {
                uint32 argv[1];

                argv[0] = value;
                wasm_runtime_call_indirect(exec_env, destructor_index, 1, argv);
            }
        }
    }

    bh_list_remove(info->thread_list, value_node);
    wasm_runtime_free(value_node);
}

static void
destroy_thread_key_value_list(bh_list *list)
{
    ThreadKeyValueNode *node, *next;

    /* There should be only one node for main thread */
    bh_assert(list->len <= 1);

    if (list->len) {
        node = bh_list_first_elem(list);
        while (node) {
            next = bh_list_elem_next(node);
            call_key_destructor(node->exec_env);
            node = next;
        }
    }
}

static ClusterInfoNode *
create_cluster_info(WASMCluster *cluster)
{
    ClusterInfoNode *node;
    bh_list_status ret;

    if (!(node = wasm_runtime_malloc(sizeof(ClusterInfoNode)))) {
        return NULL;
    }
    memset(node, 0, sizeof(ClusterInfoNode));

    node->thread_list = &node->thread_list_head;
    ret = bh_list_init(node->thread_list);
    bh_assert(ret == BH_LIST_SUCCESS);

    if (os_mutex_init(&node->key_data_list_lock) != 0) {
        wasm_runtime_free(node);
        return NULL;
    }

    node->cluster = cluster;
    if (!(node->thread_info_map = bh_hash_map_create(
              32, true, (HashFunc)thread_handle_hash,
              (KeyEqualFunc)thread_handle_equal, NULL, thread_info_destroy))) {
        os_mutex_destroy(&node->key_data_list_lock);
        wasm_runtime_free(node);
        return NULL;
    }
    os_mutex_lock(&thread_global_lock);
    ret = bh_list_insert(&cluster_info_list, node);
    bh_assert(ret == BH_LIST_SUCCESS);
    os_mutex_unlock(&thread_global_lock);

    (void)ret;
    return node;
}

static bool
destroy_cluster_info(WASMCluster *cluster)
{
    ClusterInfoNode *node = get_cluster_info(cluster);
    if (node) {
        bh_hash_map_destroy(node->thread_info_map);
        destroy_thread_key_value_list(node->thread_list);
        os_mutex_destroy(&node->key_data_list_lock);

        /* Remove from the cluster info list */
        os_mutex_lock(&thread_global_lock);
        bh_list_remove(&cluster_info_list, node);
        wasm_runtime_free(node);
        os_mutex_unlock(&thread_global_lock);
        return true;
    }
    return false;
}

static void
lib_pthread_destroy_callback(WASMCluster *cluster)
{
    destroy_cluster_info(cluster);
}

static void
delete_thread_info_node(ThreadInfoNode *thread_info)
{
    ClusterInfoNode *node;
    bool ret;
    WASMCluster *cluster = wasm_exec_env_get_cluster(thread_info->exec_env);

    if ((node = get_cluster_info(cluster))) {
        ret = bh_hash_map_remove(node->thread_info_map,
                                 (void *)(uintptr_t)thread_info->handle, NULL,
                                 NULL);
        (void)ret;
    }

    thread_info_destroy(thread_info);
}

static bool
append_thread_info_node(ThreadInfoNode *thread_info)
{
    ClusterInfoNode *node;
    WASMCluster *cluster = wasm_exec_env_get_cluster(thread_info->exec_env);

    if (!(node = get_cluster_info(cluster))) {
        if (!(node = create_cluster_info(cluster))) {
            return false;
        }
    }

    if (!bh_hash_map_insert(node->thread_info_map,
                            (void *)(uintptr_t)thread_info->handle,
                            thread_info)) {
        return false;
    }

    return true;
}

static ThreadInfoNode *
get_thread_info(wasm_exec_env_t exec_env, uint32 handle)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    ClusterInfoNode *info = get_cluster_info(cluster);

    if (!info || !handle) {
        return NULL;
    }

    return bh_hash_map_find(info->thread_info_map, (void *)(uintptr_t)handle);
}

static uint32
allocate_handle()
{
    uint32 id;
    os_mutex_lock(&thread_global_lock);
    id = handle_id++;
    os_mutex_unlock(&thread_global_lock);
    return id;
}

static void *
pthread_start_routine(void *arg)
{
    wasm_exec_env_t exec_env = (wasm_exec_env_t)arg;
    wasm_exec_env_t parent_exec_env;
    ThreadRoutineArgs *routine_args = exec_env->thread_arg;
    ThreadInfoNode *info_node = routine_args->info_node;
    uint32 argv[1];

    parent_exec_env = info_node->parent_exec_env;
    os_mutex_lock(&parent_exec_env->wait_lock);
    info_node->exec_env = exec_env;
    info_node->u.thread = exec_env->handle;
    if (!append_thread_info_node(info_node)) {
        delete_thread_info_node(info_node);
        os_cond_signal(&parent_exec_env->wait_cond);
        os_mutex_unlock(&parent_exec_env->wait_lock);
        return NULL;
    }

    info_node->status = THREAD_RUNNING;
    os_cond_signal(&parent_exec_env->wait_cond);
    os_mutex_unlock(&parent_exec_env->wait_lock);

    wasm_exec_env_set_thread_info(exec_env);
    argv[0] = routine_args->arg;

    if (!wasm_runtime_call_indirect(exec_env, routine_args->elem_index, 1,
                                    argv)) {
        /* Exception has already been spread during throwing */
    }

    /* destroy pthread key values */
    call_key_destructor(exec_env);

    wasm_runtime_free(routine_args);

    /* if the thread is joinable, store the result in its info node,
       if the other threads join this thread after exited, then we
       can return the stored result */
    if (!info_node->joinable) {
        delete_thread_info_node(info_node);
    }
    else {
        info_node->u.ret = (void *)(uintptr_t)argv[0];
#ifdef OS_ENABLE_HW_BOUND_CHECK
        if (WASM_SUSPEND_FLAGS_GET(exec_env->suspend_flags)
            & WASM_SUSPEND_FLAG_EXIT)
            /* argv[0] isn't set after longjmp(1) to
               invoke_native_with_hw_bound_check */
            info_node->u.ret = exec_env->thread_ret_value;
#endif
        /* Update node status after ret value was set */
        info_node->status = THREAD_EXIT;
    }

    return (void *)(uintptr_t)argv[0];
}

static int
pthread_create_wrapper(wasm_exec_env_t exec_env,
                       uint32 *thread,    /* thread_handle */
                       const void *attr,  /* not supported */
                       uint32 elem_index, /* entry function */
                       uint32 arg)        /* arguments buffer */
{
    wasm_module_t module = get_module(exec_env);
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasm_module_inst_t new_module_inst = NULL;
    ThreadInfoNode *info_node = NULL;
    ThreadRoutineArgs *routine_args = NULL;
    uint32 thread_handle;
    uint32 stack_size = 8192;
    uint32 aux_stack_start = 0, aux_stack_size;
    int32 ret = -1;

    bh_assert(module);
    bh_assert(module_inst);

#if WASM_ENABLE_INTERP != 0
    if (module_inst->module_type == Wasm_Module_Bytecode) {
        stack_size =
            ((WASMModuleInstance *)module_inst)->default_wasm_stack_size;
    }
#endif

#if WASM_ENABLE_AOT != 0
    if (module_inst->module_type == Wasm_Module_AoT) {
        stack_size =
            ((AOTModuleInstance *)module_inst)->default_wasm_stack_size;
    }
#endif

    if (!(new_module_inst = wasm_runtime_instantiate_internal(
              module, module_inst, exec_env, stack_size, 0, NULL, 0)))
        return -1;

    /* Set custom_data to new module instance */
    wasm_runtime_set_custom_data_internal(
        new_module_inst, wasm_runtime_get_custom_data(module_inst));

    wasm_native_inherit_contexts(new_module_inst, module_inst);

    if (!(wasm_cluster_dup_c_api_imports(new_module_inst, module_inst)))
        goto fail;

    if (!(info_node = wasm_runtime_malloc(sizeof(ThreadInfoNode))))
        goto fail;

    memset(info_node, 0, sizeof(ThreadInfoNode));
    thread_handle = allocate_handle();
    info_node->parent_exec_env = exec_env;
    info_node->handle = thread_handle;
    info_node->type = T_THREAD;
    info_node->status = THREAD_INIT;
    info_node->joinable = true;

    if (!(routine_args = wasm_runtime_malloc(sizeof(ThreadRoutineArgs))))
        goto fail;

    routine_args->arg = arg;
    routine_args->elem_index = elem_index;
    routine_args->info_node = info_node;
    routine_args->module_inst = new_module_inst;

    /* Allocate aux stack previously since exec_env->wait_lock is acquired
       below, and if the stack is allocated in wasm_cluster_create_thread,
       runtime may call the exported malloc function to allocate the stack,
       which acquires exec_env->wait again in wasm_exec_env_set_thread_info,
       and recursive lock (or hang) occurs */
    if (!wasm_cluster_allocate_aux_stack(exec_env, &aux_stack_start,
                                         &aux_stack_size)) {
        LOG_ERROR("thread manager error: "
                  "failed to allocate aux stack space for new thread");
        goto fail;
    }

    os_mutex_lock(&exec_env->wait_lock);
    ret = wasm_cluster_create_thread(
        exec_env, new_module_inst, true, aux_stack_start, aux_stack_size,
        pthread_start_routine, (void *)routine_args);
    if (ret != 0) {
        os_mutex_unlock(&exec_env->wait_lock);
        goto fail;
    }

    /* Wait for the thread routine to assign the exec_env to
       thread_info_node, otherwise the exec_env in the thread
       info node may be NULL in the next pthread API call */
    os_cond_wait(&exec_env->wait_cond, &exec_env->wait_lock);
    os_mutex_unlock(&exec_env->wait_lock);

    if (thread)
        *thread = thread_handle;

    return 0;

fail:
    if (new_module_inst)
        wasm_runtime_deinstantiate_internal(new_module_inst, true);
    if (info_node)
        wasm_runtime_free(info_node);
    if (routine_args)
        wasm_runtime_free(routine_args);
    if (aux_stack_start)
        wasm_cluster_free_aux_stack(exec_env, aux_stack_start);
    return ret;
}

static int32
pthread_join_wrapper(wasm_exec_env_t exec_env, uint32 thread,
                     int32 retval_offset) /* void **retval */
{
    uint32 *ret;
    int32 join_ret;
    void **retval;
    ThreadInfoNode *node;
    wasm_module_inst_t module_inst;
    wasm_exec_env_t target_exec_env;

    module_inst = get_module_inst(exec_env);

    /* validate addr, we can use current thread's
       module instance here as the memory is shared */
    if (!validate_app_addr(retval_offset, sizeof(int32))) {
        /* Join failed, but we don't want to terminate all threads,
           do not spread exception here */
        wasm_runtime_set_exception(module_inst, NULL);
        return -1;
    }

    retval = (void **)addr_app_to_native(retval_offset);

    node = get_thread_info(exec_env, thread);
    if (!node) {
        /* The thread has exited and not joinable, return 0 to app */
        return 0;
    }

    target_exec_env = node->exec_env;
    bh_assert(target_exec_env);

    if (node->status != THREAD_EXIT) {
        /* if the thread is still running, call the platforms join API */
        join_ret = wasm_cluster_join_thread(target_exec_env, (void **)&ret);
    }
    else {
        /* if the thread has exited, return stored results */

        /* this thread must be joinable, otherwise the
           info_node should be destroyed once exit */
        bh_assert(node->joinable);
        join_ret = 0;
        ret = node->u.ret;

        /* The target thread changes the node's status before calling
           wasm_cluster_exit_thread to exit, so here its resources may
           haven't been destroyed yet, we wait enough time to ensure that
           they are actually destroyed to avoid unexpected behavior. */
        os_mutex_lock(&exec_env->wait_lock);
        os_cond_reltimedwait(&exec_env->wait_cond, &exec_env->wait_lock, 1000);
        os_mutex_unlock(&exec_env->wait_lock);
    }

    if (retval_offset != 0)
        *(uint32 *)retval = (uint32)(uintptr_t)ret;

    return join_ret;
}

static int32
pthread_detach_wrapper(wasm_exec_env_t exec_env, uint32 thread)
{
    ThreadInfoNode *node;
    wasm_exec_env_t target_exec_env;

    node = get_thread_info(exec_env, thread);
    if (!node)
        return 0;

    node->joinable = false;

    target_exec_env = node->exec_env;
    bh_assert(target_exec_env != NULL);

    return wasm_cluster_detach_thread(target_exec_env);
}

static int32
pthread_cancel_wrapper(wasm_exec_env_t exec_env, uint32 thread)
{
    ThreadInfoNode *node;
    wasm_exec_env_t target_exec_env;

    node = get_thread_info(exec_env, thread);
    if (!node)
        return 0;

    node->status = THREAD_CANCELLED;
    node->joinable = false;

    target_exec_env = node->exec_env;
    bh_assert(target_exec_env != NULL);

    return wasm_cluster_cancel_thread(target_exec_env);
}

static int32
pthread_self_wrapper(wasm_exec_env_t exec_env)
{
    ThreadRoutineArgs *args = get_thread_arg(exec_env);
    /* If thread_arg is NULL, it's the exec_env of the main thread,
       return id 0 to app */
    if (!args)
        return 0;

    return args->info_node->handle;
}

/* emcc use __pthread_self rather than pthread_self */
static int32
__pthread_self_wrapper(wasm_exec_env_t exec_env)
{
    return pthread_self_wrapper(exec_env);
}

static void
pthread_exit_wrapper(wasm_exec_env_t exec_env, int32 retval_offset)
{
    ThreadRoutineArgs *args = get_thread_arg(exec_env);
    /* Currently exit main thread is not allowed */
    if (!args)
        return;

#if defined(OS_ENABLE_HW_BOUND_CHECK) && !defined(BH_PLATFORM_WINDOWS)
    /* If hardware bound check enabled, don't deinstantiate module inst
       and thread info node here for AoT module, as they will be freed
       in pthread_start_routine */
    if (exec_env->jmpbuf_stack_top) {
        wasm_cluster_exit_thread(exec_env, (void *)(uintptr_t)retval_offset);
    }
#endif

    /* destroy pthread key values */
    call_key_destructor(exec_env);

    if (!args->info_node->joinable) {
        delete_thread_info_node(args->info_node);
    }
    else {
        args->info_node->u.ret = (void *)(uintptr_t)retval_offset;
        /* Update node status after ret value was set */
        args->info_node->status = THREAD_EXIT;
    }

    wasm_runtime_free(args);

    /* Don't destroy exec_env->module_inst in this functuntion since
       it will be destroyed in wasm_cluster_exit_thread */
    wasm_cluster_exit_thread(exec_env, (void *)(uintptr_t)retval_offset);
}

static int32
pthread_mutex_init_wrapper(wasm_exec_env_t exec_env, uint32 *mutex, void *attr)
{
    korp_mutex *pmutex;
    ThreadInfoNode *info_node;

    if (!(pmutex = wasm_runtime_malloc(sizeof(korp_mutex)))) {
        return -1;
    }

    if (os_mutex_init(pmutex) != 0) {
        goto fail1;
    }

    if (!(info_node = wasm_runtime_malloc(sizeof(ThreadInfoNode))))
        goto fail2;

    memset(info_node, 0, sizeof(ThreadInfoNode));
    info_node->exec_env = exec_env;
    info_node->handle = allocate_handle();
    info_node->type = T_MUTEX;
    info_node->u.mutex = pmutex;
    info_node->status = MUTEX_CREATED;

    if (!append_thread_info_node(info_node))
        goto fail3;

    /* Return the mutex handle to app */
    if (mutex)
        *(uint32 *)mutex = info_node->handle;

    return 0;

fail3:
    delete_thread_info_node(info_node);
fail2:
    os_mutex_destroy(pmutex);
fail1:
    wasm_runtime_free(pmutex);

    return -1;
}

static int32
pthread_mutex_lock_wrapper(wasm_exec_env_t exec_env, uint32 *mutex)
{
    ThreadInfoNode *info_node = get_thread_info(exec_env, *mutex);
    if (!info_node || info_node->type != T_MUTEX)
        return -1;

    return os_mutex_lock(info_node->u.mutex);
}

static int32
pthread_mutex_unlock_wrapper(wasm_exec_env_t exec_env, uint32 *mutex)
{
    ThreadInfoNode *info_node = get_thread_info(exec_env, *mutex);
    if (!info_node || info_node->type != T_MUTEX)
        return -1;

    return os_mutex_unlock(info_node->u.mutex);
}

static int32
pthread_mutex_destroy_wrapper(wasm_exec_env_t exec_env, uint32 *mutex)
{
    int32 ret_val;
    ThreadInfoNode *info_node = get_thread_info(exec_env, *mutex);
    if (!info_node || info_node->type != T_MUTEX)
        return -1;

    ret_val = os_mutex_destroy(info_node->u.mutex);

    info_node->status = MUTEX_DESTROYED;
    delete_thread_info_node(info_node);

    return ret_val;
}

static int32
pthread_cond_init_wrapper(wasm_exec_env_t exec_env, uint32 *cond, void *attr)
{
    korp_cond *pcond;
    ThreadInfoNode *info_node;

    if (!(pcond = wasm_runtime_malloc(sizeof(korp_cond)))) {
        return -1;
    }

    if (os_cond_init(pcond) != 0) {
        goto fail1;
    }

    if (!(info_node = wasm_runtime_malloc(sizeof(ThreadInfoNode))))
        goto fail2;

    memset(info_node, 0, sizeof(ThreadInfoNode));
    info_node->exec_env = exec_env;
    info_node->handle = allocate_handle();
    info_node->type = T_COND;
    info_node->u.cond = pcond;
    info_node->status = COND_CREATED;

    if (!append_thread_info_node(info_node))
        goto fail3;

    /* Return the cond handle to app */
    if (cond)
        *(uint32 *)cond = info_node->handle;

    return 0;

fail3:
    delete_thread_info_node(info_node);
fail2:
    os_cond_destroy(pcond);
fail1:
    wasm_runtime_free(pcond);

    return -1;
}

static int32
pthread_cond_wait_wrapper(wasm_exec_env_t exec_env, uint32 *cond, uint32 *mutex)
{
    ThreadInfoNode *cond_info_node, *mutex_info_node;

    cond_info_node = get_thread_info(exec_env, *cond);
    if (!cond_info_node || cond_info_node->type != T_COND)
        return -1;

    mutex_info_node = get_thread_info(exec_env, *mutex);
    if (!mutex_info_node || mutex_info_node->type != T_MUTEX)
        return -1;

    return os_cond_wait(cond_info_node->u.cond, mutex_info_node->u.mutex);
}

/**
 * Currently we don't support struct timespec in built-in libc,
 * so the pthread_cond_timedwait use useconds instead
 */
static int32
pthread_cond_timedwait_wrapper(wasm_exec_env_t exec_env, uint32 *cond,
                               uint32 *mutex, uint64 useconds)
{
    ThreadInfoNode *cond_info_node, *mutex_info_node;

    cond_info_node = get_thread_info(exec_env, *cond);
    if (!cond_info_node || cond_info_node->type != T_COND)
        return -1;

    mutex_info_node = get_thread_info(exec_env, *mutex);
    if (!mutex_info_node || mutex_info_node->type != T_MUTEX)
        return -1;

    return os_cond_reltimedwait(cond_info_node->u.cond,
                                mutex_info_node->u.mutex, useconds);
}

static int32
pthread_cond_signal_wrapper(wasm_exec_env_t exec_env, uint32 *cond)
{
    ThreadInfoNode *info_node = get_thread_info(exec_env, *cond);
    if (!info_node || info_node->type != T_COND)
        return -1;

    return os_cond_signal(info_node->u.cond);
}

static int32
pthread_cond_broadcast_wrapper(wasm_exec_env_t exec_env, uint32 *cond)
{
    ThreadInfoNode *info_node = get_thread_info(exec_env, *cond);
    if (!info_node || info_node->type != T_COND)
        return -1;

    return os_cond_broadcast(info_node->u.cond);
}

static int32
pthread_cond_destroy_wrapper(wasm_exec_env_t exec_env, uint32 *cond)
{
    int32 ret_val;
    ThreadInfoNode *info_node = get_thread_info(exec_env, *cond);
    if (!info_node || info_node->type != T_COND)
        return -1;

    ret_val = os_cond_destroy(info_node->u.cond);

    info_node->status = COND_DESTROYED;
    delete_thread_info_node(info_node);

    return ret_val;
}

static int32
pthread_key_create_wrapper(wasm_exec_env_t exec_env, int32 *key,
                           int32 destructor_elem_index)
{
    uint32 i;
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    ClusterInfoNode *info = get_cluster_info(cluster);

    if (!info) {
        /* The user may call pthread_key_create in main thread,
           in this case the cluster info hasn't been created */
        if (!(info = create_cluster_info(cluster))) {
            return -1;
        }
    }

    os_mutex_lock(&info->key_data_list_lock);
    for (i = 0; i < WAMR_PTHREAD_KEYS_MAX; i++) {
        if (!info->key_data_list[i].is_created) {
            break;
        }
    }

    if (i == WAMR_PTHREAD_KEYS_MAX) {
        os_mutex_unlock(&info->key_data_list_lock);
        return -1;
    }

    info->key_data_list[i].destructor_func = destructor_elem_index;
    info->key_data_list[i].is_created = true;
    *key = i;
    os_mutex_unlock(&info->key_data_list_lock);

    return 0;
}

static int32
pthread_setspecific_wrapper(wasm_exec_env_t exec_env, int32 key,
                            int32 value_offset)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    ClusterInfoNode *info = get_cluster_info(cluster);
    int32 *key_values;

    if (!info)
        return -1;

    os_mutex_lock(&info->key_data_list_lock);

    key_values = key_value_list_lookup_or_create(exec_env, info, key);
    if (!key_values) {
        os_mutex_unlock(&info->key_data_list_lock);
        return -1;
    }

    key_values[key] = value_offset;
    os_mutex_unlock(&info->key_data_list_lock);

    return 0;
}

static int32
pthread_getspecific_wrapper(wasm_exec_env_t exec_env, int32 key)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    ClusterInfoNode *info = get_cluster_info(cluster);
    int32 ret, *key_values;

    if (!info)
        return 0;

    os_mutex_lock(&info->key_data_list_lock);

    key_values = key_value_list_lookup_or_create(exec_env, info, key);
    if (!key_values) {
        os_mutex_unlock(&info->key_data_list_lock);
        return 0;
    }

    ret = key_values[key];
    os_mutex_unlock(&info->key_data_list_lock);

    return ret;
}

static int32
pthread_key_delete_wrapper(wasm_exec_env_t exec_env, int32 key)
{
    KeyData *data;
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    ClusterInfoNode *info = get_cluster_info(cluster);

    if (!info)
        return -1;

    os_mutex_lock(&info->key_data_list_lock);
    data = key_data_list_lookup(exec_env, key);
    if (!data) {
        os_mutex_unlock(&info->key_data_list_lock);
        return -1;
    }

    memset(data, 0, sizeof(KeyData));
    os_mutex_unlock(&info->key_data_list_lock);

    return 0;
}

/**
 * Currently the memory allocator doesn't support alloc specific aligned
 * space, we wrap posix_memalign to simply malloc memory
 */
static int32
posix_memalign_wrapper(wasm_exec_env_t exec_env, void **memptr, int32 align,
                       int32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    void *p = NULL;

    *((int32 *)memptr) = module_malloc(size, (void **)&p);
    if (!p)
        return -1;

    return 0;
}

#if WASM_ENABLE_LIB_PTHREAD_SEMAPHORE != 0

static int32
sem_open_wrapper(wasm_exec_env_t exec_env, const char *name, int32 oflags,
                 int32 mode, int32 val)
{
    korp_sem *psem = NULL;
    ThreadInfoNode *info_node = NULL;

    /**
     * For RTOS, global semaphore map is safe for share the same semaphore
     * between task/pthread.
     * For Unix like system, it's dedicated for multiple processes.
     */

    if (!name) { /* avoid passing NULL to bh_hash_map_find and os_sem_open */
        return -1;
    }

    if ((info_node = bh_hash_map_find(sem_info_map, (void *)name))) {
        return info_node->handle;
    }

    if (!(psem = os_sem_open(name, oflags, mode, val))) {
        goto fail1;
    }

    if (!(info_node = wasm_runtime_malloc(sizeof(ThreadInfoNode))))
        goto fail2;

    memset(info_node, 0, sizeof(ThreadInfoNode));
    info_node->exec_env = exec_env;
    info_node->handle = allocate_handle();
    info_node->type = T_SEM;
    info_node->u.sem = psem;
    info_node->status = SEM_CREATED;

    if (!bh_hash_map_insert(sem_info_map, (void *)name, info_node))
        goto fail3;

    return info_node->handle;

fail3:
    wasm_runtime_free(info_node);
fail2:
    os_sem_close(psem);
fail1:
    return -1;
}

void
sem_fetch_cb(void *key, void *value, void *user_data)
{
    (void)key;
    SemCallbackArgs *args = user_data;
    ThreadInfoNode *info_node = value;
    if (args->handle == info_node->handle && info_node->status == SEM_CREATED) {
        args->node = info_node;
    }
}

static int32
sem_close_wrapper(wasm_exec_env_t exec_env, uint32 sem)
{
    (void)exec_env;
    int ret = -1;
    SemCallbackArgs args = { sem, NULL };

    bh_hash_map_traverse(sem_info_map, sem_fetch_cb, &args);

    if (args.node) {
        ret = os_sem_close(args.node->u.sem);
        if (ret == 0) {
            args.node->status = SEM_CLOSED;
        }
    }

    return ret;
}

static int32
sem_wait_wrapper(wasm_exec_env_t exec_env, uint32 sem)
{
    (void)exec_env;
    SemCallbackArgs args = { sem, NULL };

    bh_hash_map_traverse(sem_info_map, sem_fetch_cb, &args);

    if (args.node) {
        return os_sem_wait(args.node->u.sem);
    }

    return -1;
}

static int32
sem_trywait_wrapper(wasm_exec_env_t exec_env, uint32 sem)
{
    (void)exec_env;
    SemCallbackArgs args = { sem, NULL };

    bh_hash_map_traverse(sem_info_map, sem_fetch_cb, &args);

    if (args.node) {
        return os_sem_trywait(args.node->u.sem);
    }

    return -1;
}

static int32
sem_post_wrapper(wasm_exec_env_t exec_env, uint32 sem)
{
    (void)exec_env;
    SemCallbackArgs args = { sem, NULL };

    bh_hash_map_traverse(sem_info_map, sem_fetch_cb, &args);

    if (args.node) {
        return os_sem_post(args.node->u.sem);
    }

    return -1;
}

static int32
sem_getvalue_wrapper(wasm_exec_env_t exec_env, uint32 sem, int32 *sval)
{
    int32 ret = -1;
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    (void)exec_env;
    SemCallbackArgs args = { sem, NULL };

    if (validate_native_addr(sval, sizeof(int32))) {

        bh_hash_map_traverse(sem_info_map, sem_fetch_cb, &args);

        if (args.node) {
            ret = os_sem_getvalue(args.node->u.sem, sval);
        }
    }
    return ret;
}

static int32
sem_unlink_wrapper(wasm_exec_env_t exec_env, const char *name)
{
    (void)exec_env;
    int32 ret_val;

    ThreadInfoNode *info_node;

    if (!name) { /* avoid passing NULL to bh_hash_map_find */
        return -1;
    }

    info_node = bh_hash_map_find(sem_info_map, (void *)name);
    if (!info_node || info_node->type != T_SEM)
        return -1;

    if (info_node->status != SEM_CLOSED) {
        ret_val = os_sem_close(info_node->u.sem);
        if (ret_val != 0) {
            return ret_val;
        }
    }

    ret_val = os_sem_unlink(name);

    if (ret_val == 0) {
        bh_hash_map_remove(sem_info_map, (void *)name, NULL, NULL);
        info_node->status = SEM_DESTROYED;
        thread_info_destroy(info_node);
    }
    return ret_val;
}

#endif

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_lib_pthread[] = {
    REG_NATIVE_FUNC(pthread_create, "(**ii)i"),
    REG_NATIVE_FUNC(pthread_join, "(ii)i"),
    REG_NATIVE_FUNC(pthread_detach, "(i)i"),
    REG_NATIVE_FUNC(pthread_cancel, "(i)i"),
    REG_NATIVE_FUNC(pthread_self, "()i"),
    REG_NATIVE_FUNC(__pthread_self, "()i"),
    REG_NATIVE_FUNC(pthread_exit, "(i)"),
    REG_NATIVE_FUNC(pthread_mutex_init, "(**)i"),
    REG_NATIVE_FUNC(pthread_mutex_lock, "(*)i"),
    REG_NATIVE_FUNC(pthread_mutex_unlock, "(*)i"),
    REG_NATIVE_FUNC(pthread_mutex_destroy, "(*)i"),
    REG_NATIVE_FUNC(pthread_cond_init, "(**)i"),
    REG_NATIVE_FUNC(pthread_cond_wait, "(**)i"),
    REG_NATIVE_FUNC(pthread_cond_timedwait, "(**I)i"),
    REG_NATIVE_FUNC(pthread_cond_signal, "(*)i"),
    REG_NATIVE_FUNC(pthread_cond_broadcast, "(*)i"),
    REG_NATIVE_FUNC(pthread_cond_destroy, "(*)i"),
    REG_NATIVE_FUNC(pthread_key_create, "(*i)i"),
    REG_NATIVE_FUNC(pthread_setspecific, "(ii)i"),
    REG_NATIVE_FUNC(pthread_getspecific, "(i)i"),
    REG_NATIVE_FUNC(pthread_key_delete, "(i)i"),
    REG_NATIVE_FUNC(posix_memalign, "(*ii)i"),
#if WASM_ENABLE_LIB_PTHREAD_SEMAPHORE != 0
    REG_NATIVE_FUNC(sem_open, "($iii)i"),
    REG_NATIVE_FUNC(sem_close, "(i)i"),
    REG_NATIVE_FUNC(sem_wait, "(i)i"),
    REG_NATIVE_FUNC(sem_trywait, "(i)i"),
    REG_NATIVE_FUNC(sem_post, "(i)i"),
    REG_NATIVE_FUNC(sem_getvalue, "(i*)i"),
    REG_NATIVE_FUNC(sem_unlink, "($)i"),
#endif
};

uint32
get_lib_pthread_export_apis(NativeSymbol **p_lib_pthread_apis)
{
    *p_lib_pthread_apis = native_symbols_lib_pthread;
    return sizeof(native_symbols_lib_pthread) / sizeof(NativeSymbol);
}
