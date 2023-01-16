/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "thread_manager.h"

#if WASM_ENABLE_INTERP != 0
#include "../interpreter/wasm_runtime.h"
#endif
#if WASM_ENABLE_AOT != 0
#include "../aot/aot_runtime.h"
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
#include "debug_engine.h"
#endif

typedef struct {
    bh_list_link l;
    void (*destroy_cb)(WASMCluster *);
} DestroyCallBackNode;

static bh_list destroy_callback_list_head;
static bh_list *const destroy_callback_list = &destroy_callback_list_head;

static bh_list cluster_list_head;
static bh_list *const cluster_list = &cluster_list_head;
static korp_mutex cluster_list_lock;

typedef void (*list_visitor)(void *, void *);

static uint32 cluster_max_thread_num = CLUSTER_MAX_THREAD_NUM;

/* Set the maximum thread number, if this function is not called,
    the max thread num is defined by CLUSTER_MAX_THREAD_NUM */
void
wasm_cluster_set_max_thread_num(uint32 num)
{
    if (num > 0)
        cluster_max_thread_num = num;
}

bool
thread_manager_init()
{
    if (bh_list_init(cluster_list) != 0)
        return false;
    if (os_mutex_init(&cluster_list_lock) != 0)
        return false;
    return true;
}

void
thread_manager_destroy()
{
    WASMCluster *cluster = bh_list_first_elem(cluster_list);
    WASMCluster *next;
    while (cluster) {
        next = bh_list_elem_next(cluster);
        wasm_cluster_destroy(cluster);
        cluster = next;
    }
    wasm_cluster_cancel_all_callbacks();
    os_mutex_destroy(&cluster_list_lock);
}

static void
traverse_list(bh_list *l, list_visitor visitor, void *user_data)
{
    void *next, *node = bh_list_first_elem(l);
    while (node) {
        next = bh_list_elem_next(node);
        visitor(node, user_data);
        node = next;
    }
}

static bool
allocate_aux_stack(WASMCluster *cluster, uint32 *start, uint32 *size)
{
    uint32 i;

    /* If the module doesn't have aux stack info,
        it can't create any threads */
    if (!cluster->stack_segment_occupied)
        return false;

    os_mutex_lock(&cluster->lock);
    for (i = 0; i < cluster_max_thread_num; i++) {
        if (!cluster->stack_segment_occupied[i]) {
            if (start)
                *start = cluster->stack_tops[i];
            if (size)
                *size = cluster->stack_size;
            cluster->stack_segment_occupied[i] = true;
            os_mutex_unlock(&cluster->lock);
            return true;
        }
    }
    os_mutex_unlock(&cluster->lock);
    return false;
}

static bool
free_aux_stack(WASMCluster *cluster, uint32 start)
{
    uint32 i;

    for (i = 0; i < cluster_max_thread_num; i++) {
        if (start == cluster->stack_tops[i]) {
            os_mutex_lock(&cluster->lock);
            cluster->stack_segment_occupied[i] = false;
            os_mutex_unlock(&cluster->lock);
            return true;
        }
    }
    return false;
}

WASMCluster *
wasm_cluster_create(WASMExecEnv *exec_env)
{
    WASMCluster *cluster;
    uint64 total_size;
    uint32 aux_stack_start, aux_stack_size, i;

    bh_assert(exec_env->cluster == NULL);
    if (!(cluster = wasm_runtime_malloc(sizeof(WASMCluster)))) {
        LOG_ERROR("thread manager error: failed to allocate memory");
        return NULL;
    }
    memset(cluster, 0, sizeof(WASMCluster));

    exec_env->cluster = cluster;

    bh_list_init(&cluster->exec_env_list);
    bh_list_insert(&cluster->exec_env_list, exec_env);
    if (os_mutex_init(&cluster->lock) != 0) {
        wasm_runtime_free(cluster);
        LOG_ERROR("thread manager error: failed to init mutex");
        return NULL;
    }

    /* Prepare the aux stack top and size for every thread */
    if (!wasm_exec_env_get_aux_stack(exec_env, &aux_stack_start,
                                     &aux_stack_size)) {
        LOG_VERBOSE("No aux stack info for this module, can't create thread");

        /* If the module don't have aux stack info, don't throw error here,
            but remain stack_tops and stack_segment_occupied as NULL */
        os_mutex_lock(&cluster_list_lock);
        if (bh_list_insert(cluster_list, cluster) != 0) {
            os_mutex_unlock(&cluster_list_lock);
            goto fail;
        }
        os_mutex_unlock(&cluster_list_lock);

        return cluster;
    }

    cluster->stack_size = aux_stack_size / (cluster_max_thread_num + 1);
    if (cluster->stack_size < WASM_THREAD_AUX_STACK_SIZE_MIN) {
        goto fail;
    }
    /* Make stack size 16-byte aligned */
    cluster->stack_size = cluster->stack_size & (~15);

    /* Set initial aux stack top to the instance and
        aux stack boundary to the main exec_env */
    if (!wasm_exec_env_set_aux_stack(exec_env, aux_stack_start,
                                     cluster->stack_size))
        goto fail;

    if (cluster_max_thread_num != 0) {
        total_size = cluster_max_thread_num * sizeof(uint32);
        if (total_size >= UINT32_MAX
            || !(cluster->stack_tops =
                     wasm_runtime_malloc((uint32)total_size))) {
            goto fail;
        }
        memset(cluster->stack_tops, 0, (uint32)total_size);

        if (!(cluster->stack_segment_occupied =
                  wasm_runtime_malloc(cluster_max_thread_num * sizeof(bool)))) {
            goto fail;
        }
        memset(cluster->stack_segment_occupied, 0,
               cluster_max_thread_num * sizeof(bool));

        /* Reserve space for main instance */
        aux_stack_start -= cluster->stack_size;

        for (i = 0; i < cluster_max_thread_num; i++) {
            cluster->stack_tops[i] = aux_stack_start - cluster->stack_size * i;
        }
    }

    os_mutex_lock(&cluster_list_lock);
    if (bh_list_insert(cluster_list, cluster) != 0) {
        os_mutex_unlock(&cluster_list_lock);
        goto fail;
    }
    os_mutex_unlock(&cluster_list_lock);

    return cluster;

fail:
    if (cluster)
        wasm_cluster_destroy(cluster);

    return NULL;
}

static void
destroy_cluster_visitor(void *node, void *user_data)
{
    DestroyCallBackNode *destroy_node = (DestroyCallBackNode *)node;
    WASMCluster *cluster = (WASMCluster *)user_data;

    destroy_node->destroy_cb(cluster);
}

void
wasm_cluster_destroy(WASMCluster *cluster)
{
    traverse_list(destroy_callback_list, destroy_cluster_visitor,
                  (void *)cluster);

    /* Remove the cluster from the cluster list */
    os_mutex_lock(&cluster_list_lock);
    bh_list_remove(cluster_list, cluster);
    os_mutex_unlock(&cluster_list_lock);

    os_mutex_destroy(&cluster->lock);

    if (cluster->stack_tops)
        wasm_runtime_free(cluster->stack_tops);
    if (cluster->stack_segment_occupied)
        wasm_runtime_free(cluster->stack_segment_occupied);

#if WASM_ENABLE_DEBUG_INTERP != 0
    wasm_debug_instance_destroy(cluster);
#endif

    wasm_runtime_free(cluster);
}

static void
free_node_visitor(void *node, void *user_data)
{
    wasm_runtime_free(node);
}

void
wasm_cluster_cancel_all_callbacks()
{
    traverse_list(destroy_callback_list, free_node_visitor, NULL);
    bh_list_init(destroy_callback_list);
}

WASMCluster *
wasm_exec_env_get_cluster(WASMExecEnv *exec_env)
{
    return exec_env->cluster;
}

bool
wasm_cluster_add_exec_env(WASMCluster *cluster, WASMExecEnv *exec_env)
{
    bool ret = true;

    exec_env->cluster = cluster;

    os_mutex_lock(&cluster->lock);
    if (bh_list_insert(&cluster->exec_env_list, exec_env) != 0)
        ret = false;
    os_mutex_unlock(&cluster->lock);
    return ret;
}

bool
wasm_cluster_del_exec_env(WASMCluster *cluster, WASMExecEnv *exec_env)
{
    bool ret = true;
    bh_assert(exec_env->cluster == cluster);

#if WASM_ENABLE_DEBUG_INTERP != 0
    /* Wait for debugger control thread to process the
       stop event of this thread */
    if (cluster->debug_inst) {
        /* lock the debug_inst->wait_lock so
           other threads can't fire stop events */
        os_mutex_lock(&cluster->debug_inst->wait_lock);
        while (cluster->debug_inst->stopped_thread == exec_env) {
            os_cond_wait(&cluster->debug_inst->wait_cond,
                         &cluster->debug_inst->wait_lock);
        }
        os_mutex_unlock(&cluster->debug_inst->wait_lock);
    }
#endif

    os_mutex_lock(&cluster->lock);
    if (bh_list_remove(&cluster->exec_env_list, exec_env) != 0)
        ret = false;
    os_mutex_unlock(&cluster->lock);

    if (cluster->exec_env_list.len == 0) {
        /* exec_env_list empty, destroy the cluster */
        wasm_cluster_destroy(cluster);
    }
    return ret;
}

static WASMExecEnv *
wasm_cluster_search_exec_env(WASMCluster *cluster,
                             WASMModuleInstanceCommon *module_inst)
{
    WASMExecEnv *node = NULL;

    os_mutex_lock(&cluster->lock);
    node = bh_list_first_elem(&cluster->exec_env_list);
    while (node) {
        if (node->module_inst == module_inst) {
            os_mutex_unlock(&cluster->lock);
            return node;
        }
        node = bh_list_elem_next(node);
    }

    os_mutex_unlock(&cluster->lock);
    return NULL;
}

/* search the global cluster list to find if the given
   module instance have a corresponding exec_env */
WASMExecEnv *
wasm_clusters_search_exec_env(WASMModuleInstanceCommon *module_inst)
{
    WASMCluster *cluster = NULL;
    WASMExecEnv *exec_env = NULL;

    os_mutex_lock(&cluster_list_lock);
    cluster = bh_list_first_elem(cluster_list);
    while (cluster) {
        exec_env = wasm_cluster_search_exec_env(cluster, module_inst);
        if (exec_env) {
            os_mutex_unlock(&cluster_list_lock);
            return exec_env;
        }
        cluster = bh_list_elem_next(cluster);
    }

    os_mutex_unlock(&cluster_list_lock);
    return NULL;
}

WASMExecEnv *
wasm_cluster_spawn_exec_env(WASMExecEnv *exec_env)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasm_module_t module;
    wasm_module_inst_t new_module_inst;
#if WASM_ENABLE_LIBC_WASI != 0
    WASIContext *wasi_ctx;
#endif
    WASMExecEnv *new_exec_env;
    uint32 aux_stack_start, aux_stack_size;
    uint32 stack_size = 8192;

    if (!module_inst || !(module = wasm_exec_env_get_module(exec_env))) {
        return NULL;
    }

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
              module, true, stack_size, 0, NULL, 0))) {
        return NULL;
    }

    /* Set custom_data to new module instance */
    wasm_runtime_set_custom_data_internal(
        new_module_inst, wasm_runtime_get_custom_data(module_inst));

#if WASM_ENABLE_LIBC_WASI != 0
    wasi_ctx = wasm_runtime_get_wasi_ctx(module_inst);
    wasm_runtime_set_wasi_ctx(new_module_inst, wasi_ctx);
#endif

    new_exec_env = wasm_exec_env_create_internal(new_module_inst,
                                                 exec_env->wasm_stack_size);
    if (!new_exec_env)
        goto fail1;

    if (!allocate_aux_stack(cluster, &aux_stack_start, &aux_stack_size)) {
        LOG_ERROR("thread manager error: "
                  "failed to allocate aux stack space for new thread");
        goto fail2;
    }

    /* Set aux stack for current thread */
    if (!wasm_exec_env_set_aux_stack(new_exec_env, aux_stack_start,
                                     aux_stack_size)) {
        goto fail3;
    }

    if (!wasm_cluster_add_exec_env(cluster, new_exec_env))
        goto fail3;

    return new_exec_env;

fail3:
    /* free the allocated aux stack space */
    free_aux_stack(cluster, aux_stack_start);
fail2:
    wasm_exec_env_destroy(new_exec_env);
fail1:
    wasm_runtime_deinstantiate_internal(new_module_inst, true);

    return NULL;
}

void
wasm_cluster_destroy_spawned_exec_env(WASMExecEnv *exec_env)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    bh_assert(cluster != NULL);

    /* Free aux stack space */
    free_aux_stack(cluster, exec_env->aux_stack_bottom.bottom);
    wasm_cluster_del_exec_env(cluster, exec_env);
    wasm_exec_env_destroy_internal(exec_env);

    wasm_runtime_deinstantiate_internal(module_inst, true);
}

/* start routine of thread manager */
static void *
thread_manager_start_routine(void *arg)
{
    void *ret;
    WASMExecEnv *exec_env = (WASMExecEnv *)arg;
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster != NULL);

    exec_env->handle = os_self_thread();
    ret = exec_env->thread_start_routine(exec_env);

#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (exec_env->suspend_flags.flags & 0x08)
        ret = exec_env->thread_ret_value;
#endif

    /* Routine exit */
    /* Free aux stack space */
    free_aux_stack(cluster, exec_env->aux_stack_bottom.bottom);
    /* Detach the native thread here to ensure the resources are freed */
    wasm_cluster_detach_thread(exec_env);
#if WASM_ENABLE_DEBUG_INTERP != 0
    wasm_cluster_thread_exited(exec_env);
#endif
    /* Remove and destroy exec_env */
    wasm_cluster_del_exec_env(cluster, exec_env);
    wasm_exec_env_destroy_internal(exec_env);

    os_thread_exit(ret);
    return ret;
}

int32
wasm_cluster_create_thread(WASMExecEnv *exec_env,
                           wasm_module_inst_t module_inst,
                           void *(*thread_routine)(void *), void *arg)
{
    WASMCluster *cluster;
    WASMExecEnv *new_exec_env;
    uint32 aux_stack_start, aux_stack_size;
    korp_tid tid;

    cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);

    new_exec_env =
        wasm_exec_env_create_internal(module_inst, exec_env->wasm_stack_size);
    if (!new_exec_env)
        return -1;

    if (!allocate_aux_stack(cluster, &aux_stack_start, &aux_stack_size)) {
        LOG_ERROR("thread manager error: "
                  "failed to allocate aux stack space for new thread");
        goto fail1;
    }

    /* Set aux stack for current thread */
    if (!wasm_exec_env_set_aux_stack(new_exec_env, aux_stack_start,
                                     aux_stack_size)) {
        goto fail2;
    }

    if (!wasm_cluster_add_exec_env(cluster, new_exec_env))
        goto fail2;

    new_exec_env->thread_start_routine = thread_routine;
    new_exec_env->thread_arg = arg;

    if (0
        != os_thread_create(&tid, thread_manager_start_routine,
                            (void *)new_exec_env,
                            APP_THREAD_STACK_SIZE_DEFAULT)) {
        goto fail3;
    }

    return 0;

fail3:
    wasm_cluster_del_exec_env(cluster, new_exec_env);
fail2:
    /* free the allocated aux stack space */
    free_aux_stack(cluster, aux_stack_start);
fail1:
    wasm_exec_env_destroy(new_exec_env);
    return -1;
}

#if WASM_ENABLE_DEBUG_INTERP != 0
WASMCurrentEnvStatus *
wasm_cluster_create_exenv_status()
{
    WASMCurrentEnvStatus *status;

    if (!(status = wasm_runtime_malloc(sizeof(WASMCurrentEnvStatus)))) {
        return NULL;
    }

    status->step_count = 0;
    status->signal_flag = 0;
    status->running_status = 0;
    return status;
}

void
wasm_cluster_destroy_exenv_status(WASMCurrentEnvStatus *status)
{
    wasm_runtime_free(status);
}

inline static bool
wasm_cluster_thread_is_running(WASMExecEnv *exec_env)
{
    return exec_env->current_status->running_status == STATUS_RUNNING
           || exec_env->current_status->running_status == STATUS_STEP;
}

void
wasm_cluster_clear_thread_signal(WASMExecEnv *exec_env)
{
    exec_env->current_status->signal_flag = 0;
}

void
wasm_cluster_thread_send_signal(WASMExecEnv *exec_env, uint32 signo)
{
    exec_env->current_status->signal_flag = signo;
}

static void
notify_debug_instance(WASMExecEnv *exec_env)
{
    WASMCluster *cluster;

    cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);

    if (!cluster->debug_inst) {
        return;
    }

    on_thread_stop_event(cluster->debug_inst, exec_env);
}

void
wasm_cluster_thread_stopped(WASMExecEnv *exec_env)
{
    exec_env->current_status->running_status = STATUS_STOP;
    notify_debug_instance(exec_env);
}

void
wasm_cluster_thread_waiting_run(WASMExecEnv *exec_env)
{
    os_mutex_lock(&exec_env->wait_lock);
    while (!wasm_cluster_thread_is_running(exec_env)) {
        os_cond_wait(&exec_env->wait_cond, &exec_env->wait_lock);
    }
    os_mutex_unlock(&exec_env->wait_lock);
}

void
wasm_cluster_send_signal_all(WASMCluster *cluster, uint32 signo)
{
    WASMExecEnv *exec_env = bh_list_first_elem(&cluster->exec_env_list);
    while (exec_env) {
        wasm_cluster_thread_send_signal(exec_env, signo);
        exec_env = bh_list_elem_next(exec_env);
    }
}

void
wasm_cluster_thread_exited(WASMExecEnv *exec_env)
{
    exec_env->current_status->running_status = STATUS_EXIT;
    notify_debug_instance(exec_env);
}

void
wasm_cluster_thread_continue(WASMExecEnv *exec_env)
{
    wasm_cluster_clear_thread_signal(exec_env);
    exec_env->current_status->running_status = STATUS_RUNNING;
    os_cond_signal(&exec_env->wait_cond);
}

void
wasm_cluster_thread_step(WASMExecEnv *exec_env)
{
    exec_env->current_status->running_status = STATUS_STEP;
    os_cond_signal(&exec_env->wait_cond);
}

void
wasm_cluster_set_debug_inst(WASMCluster *cluster, WASMDebugInstance *inst)
{
    cluster->debug_inst = inst;
}

#endif /* end of WASM_ENABLE_DEBUG_INTERP */

/* Check whether the exec_env is in one of all clusters, the caller
   should add lock to the cluster list before calling us */
static bool
clusters_have_exec_env(WASMExecEnv *exec_env)
{
    WASMCluster *cluster = bh_list_first_elem(cluster_list);
    WASMExecEnv *node;

    while (cluster) {
        node = bh_list_first_elem(&cluster->exec_env_list);

        while (node) {
            if (node == exec_env) {
                bh_assert(exec_env->cluster == cluster);
                return true;
            }
            node = bh_list_elem_next(node);
        }

        cluster = bh_list_elem_next(cluster);
    }

    return false;
}

int32
wasm_cluster_join_thread(WASMExecEnv *exec_env, void **ret_val)
{
    korp_tid handle;

    os_mutex_lock(&cluster_list_lock);
    if (!clusters_have_exec_env(exec_env) || exec_env->thread_is_detached) {
        /* Invalid thread, thread has exited or thread has been detached */
        if (ret_val)
            *ret_val = NULL;
        os_mutex_unlock(&cluster_list_lock);
        return 0;
    }
    exec_env->wait_count++;
    handle = exec_env->handle;
    os_mutex_unlock(&cluster_list_lock);
    return os_thread_join(handle, ret_val);
}

int32
wasm_cluster_detach_thread(WASMExecEnv *exec_env)
{
    int32 ret = 0;

    os_mutex_lock(&cluster_list_lock);
    if (!clusters_have_exec_env(exec_env)) {
        /* Invalid thread or the thread has exited */
        os_mutex_unlock(&cluster_list_lock);
        return 0;
    }
    if (exec_env->wait_count == 0 && !exec_env->thread_is_detached) {
        /* Only detach current thread when there is no other thread
           joining it, otherwise let the system resources for the
           thread be released after joining */
        ret = os_thread_detach(exec_env->handle);
        exec_env->thread_is_detached = true;
    }
    os_mutex_unlock(&cluster_list_lock);
    return ret;
}

void
wasm_cluster_exit_thread(WASMExecEnv *exec_env, void *retval)
{
    WASMCluster *cluster;

#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (exec_env->jmpbuf_stack_top) {
        /* Store the return value in exec_env */
        exec_env->thread_ret_value = retval;
        exec_env->suspend_flags.flags |= 0x08;

#ifndef BH_PLATFORM_WINDOWS
        /* Pop all jmpbuf_node except the last one */
        while (exec_env->jmpbuf_stack_top->prev) {
            wasm_exec_env_pop_jmpbuf(exec_env);
        }
        os_longjmp(exec_env->jmpbuf_stack_top->jmpbuf, 1);
        return;
#endif
    }
#endif

    cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);
#if WASM_ENABLE_DEBUG_INTERP != 0
    wasm_cluster_clear_thread_signal(exec_env);
    wasm_cluster_thread_exited(exec_env);
#endif
    /* App exit the thread, free the resources before exit native thread */
    /* Free aux stack space */
    free_aux_stack(cluster, exec_env->aux_stack_bottom.bottom);
    /* Detach the native thread here to ensure the resources are freed */
    wasm_cluster_detach_thread(exec_env);
    /* Remove and destroy exec_env */
    wasm_cluster_del_exec_env(cluster, exec_env);
    wasm_exec_env_destroy_internal(exec_env);

    os_thread_exit(retval);
}

int32
wasm_cluster_cancel_thread(WASMExecEnv *exec_env)
{
    os_mutex_lock(&cluster_list_lock);
    if (!clusters_have_exec_env(exec_env)) {
        /* Invalid thread or the thread has exited */
        os_mutex_unlock(&cluster_list_lock);
        return 0;
    }
    os_mutex_unlock(&cluster_list_lock);

    /* Set the termination flag */
#if WASM_ENABLE_DEBUG_INTERP != 0
    wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_TERM);
#else
    exec_env->suspend_flags.flags |= 0x01;
#endif
    return 0;
}

static void
terminate_thread_visitor(void *node, void *user_data)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMExecEnv *exec_env = (WASMExecEnv *)user_data;

    if (curr_exec_env == exec_env)
        return;

    wasm_cluster_cancel_thread(curr_exec_env);
    wasm_cluster_join_thread(curr_exec_env, NULL);
}

void
wasm_cluster_terminate_all(WASMCluster *cluster)
{
    traverse_list(&cluster->exec_env_list, terminate_thread_visitor, NULL);
}

void
wasm_cluster_terminate_all_except_self(WASMCluster *cluster,
                                       WASMExecEnv *exec_env)
{
    traverse_list(&cluster->exec_env_list, terminate_thread_visitor,
                  (void *)exec_env);
}

static void
wait_for_thread_visitor(void *node, void *user_data)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMExecEnv *exec_env = (WASMExecEnv *)user_data;

    if (curr_exec_env == exec_env)
        return;

    wasm_cluster_join_thread(curr_exec_env, NULL);
}

void
wams_cluster_wait_for_all(WASMCluster *cluster)
{
    traverse_list(&cluster->exec_env_list, wait_for_thread_visitor, NULL);
}

void
wasm_cluster_wait_for_all_except_self(WASMCluster *cluster,
                                      WASMExecEnv *exec_env)
{
    traverse_list(&cluster->exec_env_list, wait_for_thread_visitor,
                  (void *)exec_env);
}

bool
wasm_cluster_register_destroy_callback(void (*callback)(WASMCluster *))
{
    DestroyCallBackNode *node;

    if (!(node = wasm_runtime_malloc(sizeof(DestroyCallBackNode)))) {
        LOG_ERROR("thread manager error: failed to allocate memory");
        return false;
    }
    node->destroy_cb = callback;
    bh_list_insert(destroy_callback_list, node);
    return true;
}

void
wasm_cluster_suspend_thread(WASMExecEnv *exec_env)
{
    /* Set the suspend flag */
    exec_env->suspend_flags.flags |= 0x02;
}

static void
suspend_thread_visitor(void *node, void *user_data)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMExecEnv *exec_env = (WASMExecEnv *)user_data;

    if (curr_exec_env == exec_env)
        return;

    wasm_cluster_suspend_thread(curr_exec_env);
}

void
wasm_cluster_suspend_all(WASMCluster *cluster)
{
    traverse_list(&cluster->exec_env_list, suspend_thread_visitor, NULL);
}

void
wasm_cluster_suspend_all_except_self(WASMCluster *cluster,
                                     WASMExecEnv *exec_env)
{
    traverse_list(&cluster->exec_env_list, suspend_thread_visitor,
                  (void *)exec_env);
}

void
wasm_cluster_resume_thread(WASMExecEnv *exec_env)
{
    exec_env->suspend_flags.flags &= ~0x02;
    os_cond_signal(&exec_env->wait_cond);
}

static void
resume_thread_visitor(void *node, void *user_data)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;

    wasm_cluster_resume_thread(curr_exec_env);
}

void
wasm_cluster_resume_all(WASMCluster *cluster)
{
    traverse_list(&cluster->exec_env_list, resume_thread_visitor, NULL);
}

static void
set_exception_visitor(void *node, void *user_data)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMExecEnv *exec_env = (WASMExecEnv *)user_data;
    WASMModuleInstanceCommon *module_inst = get_module_inst(exec_env);
    WASMModuleInstanceCommon *curr_module_inst = get_module_inst(curr_exec_env);
    const char *exception = wasm_runtime_get_exception(module_inst);
    /* skip "Exception: " */
    exception += 11;

    if (curr_exec_env != exec_env) {
        curr_module_inst = get_module_inst(curr_exec_env);
        wasm_runtime_set_exception(curr_module_inst, exception);
    }
}

void
wasm_cluster_spread_exception(WASMExecEnv *exec_env)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);

    traverse_list(&cluster->exec_env_list, set_exception_visitor, exec_env);
}

static void
set_custom_data_visitor(void *node, void *user_data)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMModuleInstanceCommon *module_inst = get_module_inst(curr_exec_env);

    wasm_runtime_set_custom_data_internal(module_inst, user_data);
}

void
wasm_cluster_spread_custom_data(WASMModuleInstanceCommon *module_inst,
                                void *custom_data)
{
    WASMExecEnv *exec_env = wasm_clusters_search_exec_env(module_inst);

    if (exec_env == NULL) {
        /* Maybe threads have not been started yet. */
        wasm_runtime_set_custom_data_internal(module_inst, custom_data);
    }
    else {
        WASMCluster *cluster;

        cluster = wasm_exec_env_get_cluster(exec_env);
        bh_assert(cluster);

        traverse_list(&cluster->exec_env_list, set_custom_data_visitor,
                      custom_data);
    }
}
