/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "thread_manager.h"
#include "../common/wasm_c_api_internal.h"

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

static korp_mutex _exception_lock;

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
    if (os_mutex_init(&_exception_lock) != 0) {
        os_mutex_destroy(&cluster_list_lock);
        return false;
    }
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
    os_mutex_destroy(&_exception_lock);
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

/* Assumes cluster->lock is locked */
static bool
safe_traverse_exec_env_list(WASMCluster *cluster, list_visitor visitor,
                            void *user_data)
{
    Vector proc_nodes;
    void *node;
    bool ret = true;

    if (!bh_vector_init(&proc_nodes, cluster->exec_env_list.len, sizeof(void *),
                        false)) {
        ret = false;
        goto final;
    }

    node = bh_list_first_elem(&cluster->exec_env_list);

    while (node) {
        bool already_processed = false;
        void *proc_node;
        uint32 i;
        for (i = 0; i < (uint32)bh_vector_size(&proc_nodes); i++) {
            if (!bh_vector_get(&proc_nodes, i, &proc_node)) {
                ret = false;
                goto final;
            }
            if (proc_node == node) {
                already_processed = true;
                break;
            }
        }
        if (already_processed) {
            node = bh_list_elem_next(node);
            continue;
        }

        os_mutex_unlock(&cluster->lock);
        visitor(node, user_data);
        os_mutex_lock(&cluster->lock);
        if (!bh_vector_append(&proc_nodes, &node)) {
            ret = false;
            goto final;
        }

        node = bh_list_first_elem(&cluster->exec_env_list);
    }

final:
    bh_vector_destroy(&proc_nodes);

    return ret;
}

/* The caller must not have any locks */
bool
wasm_cluster_allocate_aux_stack(WASMExecEnv *exec_env, uint64 *p_start,
                                uint32 *p_size)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
#if WASM_ENABLE_HEAP_AUX_STACK_ALLOCATION != 0
    WASMModuleInstanceCommon *module_inst =
        wasm_exec_env_get_module_inst(exec_env);
    uint64 stack_end;

    stack_end = wasm_runtime_module_malloc_internal(module_inst, exec_env,
                                                    cluster->stack_size, NULL);
    *p_start = stack_end + cluster->stack_size;
    *p_size = cluster->stack_size;

    return stack_end != 0;
#else
    uint32 i;

    /* If the module doesn't have aux stack info,
        it can't create any threads */

    os_mutex_lock(&cluster->lock);
    if (!cluster->stack_segment_occupied) {
        os_mutex_unlock(&cluster->lock);
        return false;
    }

    for (i = 0; i < cluster_max_thread_num; i++) {
        if (!cluster->stack_segment_occupied[i]) {
            if (p_start)
                *p_start = cluster->stack_tops[i];
            if (p_size)
                *p_size = cluster->stack_size;
            cluster->stack_segment_occupied[i] = true;
            os_mutex_unlock(&cluster->lock);
            return true;
        }
    }
    os_mutex_unlock(&cluster->lock);

    return false;
#endif
}

/* The caller must not have any locks */
bool
wasm_cluster_free_aux_stack(WASMExecEnv *exec_env, uint64 start)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);

#if WASM_ENABLE_HEAP_AUX_STACK_ALLOCATION != 0
    WASMModuleInstanceCommon *module_inst =
        wasm_exec_env_get_module_inst(exec_env);

    if (!wasm_exec_env_is_aux_stack_managed_by_runtime(exec_env)) {
        return true;
    }

    bh_assert(start >= cluster->stack_size);

    wasm_runtime_module_free_internal(module_inst, exec_env,
                                      start - cluster->stack_size);

    return true;
#else
    uint32 i;

    os_mutex_lock(&cluster->lock);
    for (i = 0; i < cluster_max_thread_num; i++) {
        if (start == cluster->stack_tops[i]) {
            cluster->stack_segment_occupied[i] = false;
            os_mutex_unlock(&cluster->lock);
            return true;
        }
    }
    os_mutex_unlock(&cluster->lock);
    return false;
#endif
}

WASMCluster *
wasm_cluster_create(WASMExecEnv *exec_env)
{
    WASMCluster *cluster;
    uint32 aux_stack_size;
    uint64 aux_stack_start;

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
#if WASM_ENABLE_LIB_WASI_THREADS == 0
        LOG_VERBOSE("No aux stack info for this module, can't create thread");
#endif

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

#if WASM_ENABLE_HEAP_AUX_STACK_ALLOCATION != 0
    cluster->stack_size = aux_stack_size;
#else
    cluster->stack_size = aux_stack_size / (cluster_max_thread_num + 1);
    if (cluster->stack_size < WASM_THREAD_AUX_STACK_SIZE_MIN) {
        goto fail;
    }
    /* Make stack size 16-byte aligned */
    cluster->stack_size = cluster->stack_size & (~15);
#endif

    /* Set initial aux stack top to the instance and
        aux stack boundary to the main exec_env */
    if (!wasm_exec_env_set_aux_stack(exec_env, aux_stack_start,
                                     cluster->stack_size))
        goto fail;

#if WASM_ENABLE_HEAP_AUX_STACK_ALLOCATION == 0
    if (cluster_max_thread_num != 0) {
        uint64 total_size = cluster_max_thread_num * sizeof(uint64);
        uint32 i;
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
            cluster->stack_tops[i] =
                aux_stack_start - (uint64)cluster->stack_size * i;
        }
    }
#endif

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

#if WASM_ENABLE_HEAP_AUX_STACK_ALLOCATION == 0
    if (cluster->stack_tops)
        wasm_runtime_free(cluster->stack_tops);
    if (cluster->stack_segment_occupied)
        wasm_runtime_free(cluster->stack_segment_occupied);
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
    wasm_debug_instance_destroy(cluster);
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    bh_vector_destroy(&cluster->exception_frames);
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

/* The caller must lock cluster->lock */
static bool
wasm_cluster_add_exec_env(WASMCluster *cluster, WASMExecEnv *exec_env)
{
    bool ret = true;

    exec_env->cluster = cluster;

    if (cluster->exec_env_list.len == cluster_max_thread_num + 1) {
        LOG_ERROR("thread manager error: "
                  "maximum number of threads exceeded");
        ret = false;
    }

    if (ret && bh_list_insert(&cluster->exec_env_list, exec_env) != 0)
        ret = false;

    return ret;
}

static bool
wasm_cluster_del_exec_env_internal(WASMCluster *cluster, WASMExecEnv *exec_env,
                                   bool can_destroy_cluster)
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
            /* either wakes up by signal or by 1-second timeout */
            os_cond_reltimedwait(&cluster->debug_inst->wait_cond,
                                 &cluster->debug_inst->wait_lock, 1000000);
        }
        os_mutex_unlock(&cluster->debug_inst->wait_lock);
    }
#endif
    if (bh_list_remove(&cluster->exec_env_list, exec_env) != 0)
        ret = false;

    if (can_destroy_cluster) {
        if (cluster->exec_env_list.len == 0) {
            /* exec_env_list empty, destroy the cluster */
            wasm_cluster_destroy(cluster);
        }
    }
    else {
        /* Don't destroy cluster as cluster->lock is being used */
    }

    return ret;
}

/* The caller should lock cluster->lock for thread safety */
bool
wasm_cluster_del_exec_env(WASMCluster *cluster, WASMExecEnv *exec_env)
{
    return wasm_cluster_del_exec_env_internal(cluster, exec_env, true);
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
    WASMExecEnv *new_exec_env;
    uint32 aux_stack_size;
    uint64 aux_stack_start;
    uint32 stack_size = 8192;

    if (!module_inst || !(module = wasm_exec_env_get_module(exec_env))) {
        return NULL;
    }

    if (!(new_module_inst = wasm_runtime_instantiate_internal(
              module, module_inst, exec_env, stack_size, 0, 0, NULL, 0))) {
        return NULL;
    }

    /* Set custom_data to new module instance */
    wasm_runtime_set_custom_data_internal(
        new_module_inst, wasm_runtime_get_custom_data(module_inst));

    wasm_native_inherit_contexts(new_module_inst, module_inst);

    if (!(wasm_cluster_dup_c_api_imports(new_module_inst, module_inst))) {
        goto fail1;
    }

    if (!wasm_cluster_allocate_aux_stack(exec_env, &aux_stack_start,
                                         &aux_stack_size)) {
        LOG_ERROR("thread manager error: "
                  "failed to allocate aux stack space for new thread");
        goto fail1;
    }

    os_mutex_lock(&cluster->lock);

    if (cluster->has_exception || cluster->processing) {
        goto fail2;
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

    new_exec_env = wasm_exec_env_create_internal(new_module_inst,
                                                 exec_env->wasm_stack_size);
    if (!new_exec_env) {
        goto fail2;
    }

    /* Set aux stack for current thread */
    if (!wasm_exec_env_set_aux_stack(new_exec_env, aux_stack_start,
                                     aux_stack_size)) {
        goto fail3;
    }
    new_exec_env->is_aux_stack_allocated = true;

    /* Inherit suspend_flags of parent thread */
    new_exec_env->suspend_flags.flags =
        (exec_env->suspend_flags.flags & WASM_SUSPEND_FLAG_INHERIT_MASK);

    if (!wasm_cluster_add_exec_env(cluster, new_exec_env)) {
        goto fail3;
    }

    os_mutex_unlock(&cluster->lock);

    return new_exec_env;

fail3:
    wasm_exec_env_destroy_internal(new_exec_env);
fail2:
    os_mutex_unlock(&cluster->lock);
    /* free the allocated aux stack space */
    wasm_cluster_free_aux_stack(exec_env, aux_stack_start);
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
    WASMExecEnv *exec_env_tls = NULL;

#ifdef OS_ENABLE_HW_BOUND_CHECK
    /* Note: free_aux_stack can execute the module's "free" function
     * using the specified exec_env. In case of OS_ENABLE_HW_BOUND_CHECK,
     * it needs to match the TLS exec_env if available. (Consider a native
     * function which calls wasm_cluster_destroy_spawned_exec_env.)
     */
    exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    if (exec_env_tls == NULL) {
        exec_env_tls = exec_env;
    }

    /* Free aux stack space which was allocated in
       wasm_cluster_spawn_exec_env */
    bh_assert(exec_env_tls->is_aux_stack_allocated);
    wasm_cluster_free_aux_stack(exec_env_tls,
                                (uint64)exec_env->aux_stack_bottom);

    os_mutex_lock(&cluster->lock);

    /* Remove exec_env */
    wasm_cluster_del_exec_env_internal(cluster, exec_env, false);
    /* Destroy exec_env */
    wasm_exec_env_destroy_internal(exec_env);
    /* Routine exit, destroy instance */
    wasm_runtime_deinstantiate_internal(module_inst, true);

    os_mutex_unlock(&cluster->lock);
}

/* start routine of thread manager */
static void *
thread_manager_start_routine(void *arg)
{
    void *ret;
    WASMExecEnv *exec_env = (WASMExecEnv *)arg;
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    WASMModuleInstanceCommon *module_inst =
        wasm_exec_env_get_module_inst(exec_env);

    bh_assert(cluster != NULL);
    bh_assert(module_inst != NULL);

    os_mutex_lock(&exec_env->wait_lock);
    exec_env->handle = os_self_thread();
    /* Notify the parent thread to continue running */
    os_cond_signal(&exec_env->wait_cond);
    os_mutex_unlock(&exec_env->wait_lock);

    ret = exec_env->thread_start_routine(exec_env);

#ifdef OS_ENABLE_HW_BOUND_CHECK
    os_mutex_lock(&exec_env->wait_lock);
    if (WASM_SUSPEND_FLAGS_GET(exec_env->suspend_flags)
        & WASM_SUSPEND_FLAG_EXIT)
        ret = exec_env->thread_ret_value;
    os_mutex_unlock(&exec_env->wait_lock);
#endif

    /* Routine exit */

#if WASM_ENABLE_DEBUG_INTERP != 0
    wasm_cluster_thread_exited(exec_env);
#endif

    /* Free aux stack space */
    if (exec_env->is_aux_stack_allocated)
        wasm_cluster_free_aux_stack(exec_env,
                                    (uint64)exec_env->aux_stack_bottom);

    os_mutex_lock(&cluster_list_lock);

    os_mutex_lock(&cluster->lock);

    /* Detach the native thread here to ensure the resources are freed */
    if (exec_env->wait_count == 0 && !exec_env->thread_is_detached) {
        /* Only detach current thread when there is no other thread
           joining it, otherwise let the system resources for the
           thread be released after joining */
        os_thread_detach(exec_env->handle);
        /* No need to set exec_env->thread_is_detached to true here
           since we will exit soon */
    }

#if WASM_ENABLE_PERF_PROFILING != 0
    os_printf("============= Spawned thread ===========\n");
    wasm_runtime_dump_perf_profiling(module_inst);
    os_printf("========================================\n");
#endif

    /* Remove exec_env */
    wasm_cluster_del_exec_env_internal(cluster, exec_env, false);
    /* Destroy exec_env */
    wasm_exec_env_destroy_internal(exec_env);
    /* Routine exit, destroy instance */
    wasm_runtime_deinstantiate_internal(module_inst, true);

    os_mutex_unlock(&cluster->lock);

    os_mutex_unlock(&cluster_list_lock);

    os_thread_exit(ret);
    return ret;
}

int32
wasm_cluster_create_thread(WASMExecEnv *exec_env,
                           wasm_module_inst_t module_inst,
                           bool is_aux_stack_allocated, uint64 aux_stack_start,
                           uint32 aux_stack_size,
                           void *(*thread_routine)(void *), void *arg)
{
    WASMCluster *cluster;
    WASMExecEnv *new_exec_env;
    korp_tid tid;

    cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);

    os_mutex_lock(&cluster->lock);

    if (cluster->has_exception || cluster->processing) {
        goto fail1;
    }

    new_exec_env =
        wasm_exec_env_create_internal(module_inst, exec_env->wasm_stack_size);
    if (!new_exec_env)
        goto fail1;

    if (is_aux_stack_allocated) {
        /* Set aux stack for current thread */
        if (!wasm_exec_env_set_aux_stack(new_exec_env, aux_stack_start,
                                         aux_stack_size)) {
            goto fail2;
        }
        new_exec_env->is_aux_stack_allocated = true;
    }
    else {
        /* Disable aux stack */
        new_exec_env->aux_stack_boundary = 0;
        new_exec_env->aux_stack_bottom = UINTPTR_MAX;
        new_exec_env->is_aux_stack_allocated = false;
    }

    /* Inherit suspend_flags of parent thread */
    new_exec_env->suspend_flags.flags =
        (exec_env->suspend_flags.flags & WASM_SUSPEND_FLAG_INHERIT_MASK);

    if (!wasm_cluster_add_exec_env(cluster, new_exec_env))
        goto fail2;

    new_exec_env->thread_start_routine = thread_routine;
    new_exec_env->thread_arg = arg;

    os_mutex_lock(&new_exec_env->wait_lock);

    if (0
        != os_thread_create(&tid, thread_manager_start_routine,
                            (void *)new_exec_env,
                            APP_THREAD_STACK_SIZE_DEFAULT)) {
        os_mutex_unlock(&new_exec_env->wait_lock);
        goto fail3;
    }

    /* Wait until the new_exec_env->handle is set to avoid it is
       illegally accessed after unlocking cluster->lock */
    os_cond_wait(&new_exec_env->wait_cond, &new_exec_env->wait_lock);
    os_mutex_unlock(&new_exec_env->wait_lock);

    os_mutex_unlock(&cluster->lock);

    return 0;

fail3:
    wasm_cluster_del_exec_env_internal(cluster, new_exec_env, false);
fail2:
    wasm_exec_env_destroy_internal(new_exec_env);
fail1:
    os_mutex_unlock(&cluster->lock);

    return -1;
}

bool
wasm_cluster_dup_c_api_imports(WASMModuleInstanceCommon *module_inst_dst,
                               const WASMModuleInstanceCommon *module_inst_src)
{
    /* workaround about passing instantiate-linking information */
    CApiFuncImport **new_c_api_func_imports = NULL;
    CApiFuncImport *c_api_func_imports = NULL;
    uint32 import_func_count = 0;
    uint32 size_in_bytes = 0;

#if WASM_ENABLE_INTERP != 0
    if (module_inst_src->module_type == Wasm_Module_Bytecode) {
        new_c_api_func_imports =
            &(((WASMModuleInstance *)module_inst_dst)->c_api_func_imports);
        c_api_func_imports =
            ((const WASMModuleInstance *)module_inst_src)->c_api_func_imports;
        import_func_count =
            ((WASMModule *)(((const WASMModuleInstance *)module_inst_src)
                                ->module))
                ->import_function_count;
    }
#endif
#if WASM_ENABLE_AOT != 0
    if (module_inst_src->module_type == Wasm_Module_AoT) {
        new_c_api_func_imports =
            &(((AOTModuleInstance *)module_inst_dst)->c_api_func_imports);
        c_api_func_imports =
            ((const AOTModuleInstance *)module_inst_src)->c_api_func_imports;
        import_func_count =
            ((AOTModule *)(((AOTModuleInstance *)module_inst_src)->module))
                ->import_func_count;
    }
#endif

    if (import_func_count != 0 && c_api_func_imports) {
        size_in_bytes = sizeof(CApiFuncImport) * import_func_count;
        *new_c_api_func_imports = wasm_runtime_malloc(size_in_bytes);
        if (!(*new_c_api_func_imports))
            return false;

        bh_memcpy_s(*new_c_api_func_imports, size_in_bytes, c_api_func_imports,
                    size_in_bytes);
    }
    return true;
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

static void
notify_debug_instance_exit(WASMExecEnv *exec_env)
{
    WASMCluster *cluster;

    cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);

    if (!cluster->debug_inst) {
        return;
    }

    on_thread_exit_event(cluster->debug_inst, exec_env);
}

void
wasm_cluster_thread_waiting_run(WASMExecEnv *exec_env)
{
    exec_env->current_status->running_status = STATUS_STOP;
    notify_debug_instance(exec_env);

    while (!wasm_cluster_thread_is_running(exec_env)) {
        os_cond_wait(&exec_env->wait_cond, &exec_env->wait_lock);
    }
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
    notify_debug_instance_exit(exec_env);
}

void
wasm_cluster_thread_continue(WASMExecEnv *exec_env)
{
    os_mutex_lock(&exec_env->wait_lock);
    wasm_cluster_clear_thread_signal(exec_env);
    exec_env->current_status->running_status = STATUS_RUNNING;
    os_cond_signal(&exec_env->wait_cond);
    os_mutex_unlock(&exec_env->wait_lock);
}

void
wasm_cluster_thread_step(WASMExecEnv *exec_env)
{
    os_mutex_lock(&exec_env->wait_lock);
    exec_env->current_status->running_status = STATUS_STEP;
    os_cond_signal(&exec_env->wait_cond);
    os_mutex_unlock(&exec_env->wait_lock);
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
        os_mutex_lock(&cluster->lock);
        node = bh_list_first_elem(&cluster->exec_env_list);

        while (node) {
            if (node == exec_env) {
                bh_assert(exec_env->cluster == cluster);
                os_mutex_unlock(&cluster->lock);
                return true;
            }
            node = bh_list_elem_next(node);
        }
        os_mutex_unlock(&cluster->lock);

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

    os_mutex_lock(&exec_env->wait_lock);
    exec_env->wait_count++;
    handle = exec_env->handle;
    os_mutex_unlock(&exec_env->wait_lock);

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
    WASMModuleInstanceCommon *module_inst;

#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (exec_env->jmpbuf_stack_top) {
        /* Store the return value in exec_env */
        exec_env->thread_ret_value = retval;

        WASM_SUSPEND_FLAGS_FETCH_OR(exec_env->suspend_flags,
                                    WASM_SUSPEND_FLAG_EXIT);

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

    /* Free aux stack space */
    if (exec_env->is_aux_stack_allocated)
        wasm_cluster_free_aux_stack(exec_env,
                                    (uint64)exec_env->aux_stack_bottom);

    /* App exit the thread, free the resources before exit native thread */

    os_mutex_lock(&cluster_list_lock);

    os_mutex_lock(&cluster->lock);

    /* Detach the native thread here to ensure the resources are freed */
    if (exec_env->wait_count == 0 && !exec_env->thread_is_detached) {
        /* Only detach current thread when there is no other thread
           joining it, otherwise let the system resources for the
           thread be released after joining */
        os_thread_detach(exec_env->handle);
        /* No need to set exec_env->thread_is_detached to true here
           since we will exit soon */
    }

    module_inst = exec_env->module_inst;

    /* Remove exec_env */
    wasm_cluster_del_exec_env_internal(cluster, exec_env, false);
    /* Destroy exec_env */
    wasm_exec_env_destroy_internal(exec_env);
    /* Routine exit, destroy instance */
    wasm_runtime_deinstantiate_internal(module_inst, true);

    os_mutex_unlock(&cluster->lock);

    os_mutex_unlock(&cluster_list_lock);

    os_thread_exit(retval);
}

static void
set_thread_cancel_flags(WASMExecEnv *exec_env)
{
    os_mutex_lock(&exec_env->wait_lock);

#if WASM_ENABLE_DEBUG_INTERP != 0
    wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_TERM);
#endif
    WASM_SUSPEND_FLAGS_FETCH_OR(exec_env->suspend_flags,
                                WASM_SUSPEND_FLAG_TERMINATE);

    os_mutex_unlock(&exec_env->wait_lock);

#ifdef OS_ENABLE_WAKEUP_BLOCKING_OP
    wasm_runtime_interrupt_blocking_op(exec_env);
#endif
}

static void
clear_thread_cancel_flags(WASMExecEnv *exec_env)
{
    os_mutex_lock(&exec_env->wait_lock);
    WASM_SUSPEND_FLAGS_FETCH_AND(exec_env->suspend_flags,
                                 ~WASM_SUSPEND_FLAG_TERMINATE);
    os_mutex_unlock(&exec_env->wait_lock);
}

int32
wasm_cluster_cancel_thread(WASMExecEnv *exec_env)
{
    os_mutex_lock(&cluster_list_lock);

    if (!exec_env->cluster) {
        os_mutex_unlock(&cluster_list_lock);
        return 0;
    }

    if (!clusters_have_exec_env(exec_env)) {
        /* Invalid thread or the thread has exited */
        goto final;
    }

    set_thread_cancel_flags(exec_env);

final:
    os_mutex_unlock(&cluster_list_lock);

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
    os_mutex_lock(&cluster->lock);
    cluster->processing = true;

    safe_traverse_exec_env_list(cluster, terminate_thread_visitor, NULL);

    cluster->processing = false;
    os_mutex_unlock(&cluster->lock);
}

void
wasm_cluster_terminate_all_except_self(WASMCluster *cluster,
                                       WASMExecEnv *exec_env)
{
    os_mutex_lock(&cluster->lock);
    cluster->processing = true;

    safe_traverse_exec_env_list(cluster, terminate_thread_visitor,
                                (void *)exec_env);

    cluster->processing = false;
    os_mutex_unlock(&cluster->lock);
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
wasm_cluster_wait_for_all(WASMCluster *cluster)
{
    os_mutex_lock(&cluster->lock);
    cluster->processing = true;

    safe_traverse_exec_env_list(cluster, wait_for_thread_visitor, NULL);

    cluster->processing = false;
    os_mutex_unlock(&cluster->lock);
}

void
wasm_cluster_wait_for_all_except_self(WASMCluster *cluster,
                                      WASMExecEnv *exec_env)
{
    os_mutex_lock(&cluster->lock);
    cluster->processing = true;

    safe_traverse_exec_env_list(cluster, wait_for_thread_visitor,
                                (void *)exec_env);

    cluster->processing = false;
    os_mutex_unlock(&cluster->lock);
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
    WASM_SUSPEND_FLAGS_FETCH_OR(exec_env->suspend_flags,
                                WASM_SUSPEND_FLAG_SUSPEND);
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
    os_mutex_lock(&cluster->lock);
    traverse_list(&cluster->exec_env_list, suspend_thread_visitor, NULL);
    os_mutex_unlock(&cluster->lock);
}

void
wasm_cluster_suspend_all_except_self(WASMCluster *cluster,
                                     WASMExecEnv *exec_env)
{
    os_mutex_lock(&cluster->lock);
    traverse_list(&cluster->exec_env_list, suspend_thread_visitor,
                  (void *)exec_env);
    os_mutex_unlock(&cluster->lock);
}

void
wasm_cluster_resume_thread(WASMExecEnv *exec_env)
{
    WASM_SUSPEND_FLAGS_FETCH_AND(exec_env->suspend_flags,
                                 ~WASM_SUSPEND_FLAG_SUSPEND);
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
    os_mutex_lock(&cluster->lock);
    traverse_list(&cluster->exec_env_list, resume_thread_visitor, NULL);
    os_mutex_unlock(&cluster->lock);
}

struct spread_exception_data {
    WASMExecEnv *skip;
    const char *exception;
};

static void
set_exception_visitor(void *node, void *user_data)
{
    const struct spread_exception_data *data = user_data;
    WASMExecEnv *exec_env = (WASMExecEnv *)node;

    if (exec_env != data->skip) {
        WASMModuleInstance *wasm_inst =
            (WASMModuleInstance *)get_module_inst(exec_env);

        exception_lock(wasm_inst);
        if (data->exception != NULL) {
            snprintf(wasm_inst->cur_exception, sizeof(wasm_inst->cur_exception),
                     "Exception: %s", data->exception);
        }
        else {
            wasm_inst->cur_exception[0] = '\0';
        }
        exception_unlock(wasm_inst);

        /* Terminate the thread so it can exit from dead loops */
        if (data->exception != NULL) {
            set_thread_cancel_flags(exec_env);
        }
        else {
            clear_thread_cancel_flags(exec_env);
        }
    }
}

void
wasm_cluster_set_exception(WASMExecEnv *exec_env, const char *exception)
{
    const bool has_exception = exception != NULL;
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);

    struct spread_exception_data data;
    data.skip = NULL;
    data.exception = exception;

    os_mutex_lock(&cluster->lock);
#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (has_exception) {
        /* Save the stack frames of the crashed thread into the cluster */
        WASMModuleInstance *module_inst =
            (WASMModuleInstance *)get_module_inst(exec_env);

#if WASM_ENABLE_INTERP != 0
        if (module_inst->module_type == Wasm_Module_Bytecode
            && wasm_interp_create_call_stack(exec_env)) {
            wasm_frame_vec_clone_internal(module_inst->frames,
                                          &cluster->exception_frames);
        }
#endif

#if WASM_ENABLE_AOT != 0
        if (module_inst->module_type == Wasm_Module_AoT
            && aot_create_call_stack(exec_env)) {
            wasm_frame_vec_clone_internal(module_inst->frames,
                                          &cluster->exception_frames);
        }
#endif
    }
#endif /* WASM_ENABLE_DUMP_CALL_STACK != 0 */
    cluster->has_exception = has_exception;
    traverse_list(&cluster->exec_env_list, set_exception_visitor, &data);
    os_mutex_unlock(&cluster->lock);
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

        os_mutex_lock(&cluster->lock);
        traverse_list(&cluster->exec_env_list, set_custom_data_visitor,
                      custom_data);
        os_mutex_unlock(&cluster->lock);
    }
}

#if WASM_ENABLE_SHARED_HEAP != 0
static void
attach_shared_heap_visitor(void *node, void *heap)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMModuleInstanceCommon *module_inst = get_module_inst(curr_exec_env);

    wasm_runtime_attach_shared_heap_internal(module_inst, heap);
}

static void
detach_shared_heap_visitor(void *node, void *heap)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMModuleInstanceCommon *module_inst = get_module_inst(curr_exec_env);

    (void)heap;
    wasm_runtime_detach_shared_heap_internal(module_inst);
}

bool
wasm_cluster_attach_shared_heap(WASMModuleInstanceCommon *module_inst,
                                WASMSharedHeap *heap)
{
    WASMExecEnv *exec_env = wasm_clusters_search_exec_env(module_inst);

    if (exec_env == NULL) {
        /* Maybe threads have not been started yet. */
        return wasm_runtime_attach_shared_heap_internal(module_inst, heap);
    }
    else {
        WASMCluster *cluster;

        cluster = wasm_exec_env_get_cluster(exec_env);
        bh_assert(cluster);

        os_mutex_lock(&cluster->lock);
        /* Try attaching shared heap to this module instance first
           to ensure that we can attach it to all other instances. */
        if (!wasm_runtime_attach_shared_heap_internal(module_inst, heap)) {
            os_mutex_unlock(&cluster->lock);
            return false;
        }
        /* Detach the shared heap so it can be attached again. */
        wasm_runtime_detach_shared_heap_internal(module_inst);
        traverse_list(&cluster->exec_env_list, attach_shared_heap_visitor,
                      heap);
        os_mutex_unlock(&cluster->lock);
    }

    return true;
}

void
wasm_cluster_detach_shared_heap(WASMModuleInstanceCommon *module_inst)
{
    WASMExecEnv *exec_env = wasm_clusters_search_exec_env(module_inst);

    if (exec_env == NULL) {
        /* Maybe threads have not been started yet. */
        wasm_runtime_detach_shared_heap_internal(module_inst);
    }
    else {
        WASMCluster *cluster;

        cluster = wasm_exec_env_get_cluster(exec_env);
        bh_assert(cluster);

        os_mutex_lock(&cluster->lock);
        traverse_list(&cluster->exec_env_list, detach_shared_heap_visitor,
                      NULL);
        os_mutex_unlock(&cluster->lock);
    }
}
#endif

#if WASM_ENABLE_MODULE_INST_CONTEXT != 0
struct inst_set_context_data {
    void *key;
    void *ctx;
};

static void
set_context_visitor(void *node, void *user_data)
{
    WASMExecEnv *curr_exec_env = (WASMExecEnv *)node;
    WASMModuleInstanceCommon *module_inst = get_module_inst(curr_exec_env);
    const struct inst_set_context_data *data = user_data;

    wasm_runtime_set_context(module_inst, data->key, data->ctx);
}

void
wasm_cluster_set_context(WASMModuleInstanceCommon *module_inst, void *key,
                         void *ctx)
{
    WASMExecEnv *exec_env = wasm_clusters_search_exec_env(module_inst);

    if (exec_env == NULL) {
        /* Maybe threads have not been started yet. */
        wasm_runtime_set_context(module_inst, key, ctx);
    }
    else {
        WASMCluster *cluster;
        struct inst_set_context_data data;
        data.key = key;
        data.ctx = ctx;

        cluster = wasm_exec_env_get_cluster(exec_env);
        bh_assert(cluster);

        os_mutex_lock(&cluster->lock);
        traverse_list(&cluster->exec_env_list, set_context_visitor, &data);
        os_mutex_unlock(&cluster->lock);
    }
}
#endif /* WASM_ENABLE_MODULE_INST_CONTEXT != 0 */

bool
wasm_cluster_is_thread_terminated(WASMExecEnv *exec_env)
{
    os_mutex_lock(&exec_env->wait_lock);
    bool is_thread_terminated = (WASM_SUSPEND_FLAGS_GET(exec_env->suspend_flags)
                                 & WASM_SUSPEND_FLAG_TERMINATE)
                                    ? true
                                    : false;
    os_mutex_unlock(&exec_env->wait_lock);

    return is_thread_terminated;
}

void
exception_lock(WASMModuleInstance *module_inst)
{
    /*
     * Note: this lock could be per module instance if desirable.
     * We can revisit on AOT version bump.
     * It probably doesn't matter though because the exception handling
     * logic should not be executed too frequently anyway.
     */
    os_mutex_lock(&_exception_lock);
}

void
exception_unlock(WASMModuleInstance *module_inst)
{
    os_mutex_unlock(&_exception_lock);
}

void
wasm_cluster_traverse_lock(WASMExecEnv *exec_env)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);
    os_mutex_lock(&cluster->lock);
}

void
wasm_cluster_traverse_unlock(WASMExecEnv *exec_env)
{
    WASMCluster *cluster = wasm_exec_env_get_cluster(exec_env);
    bh_assert(cluster);
    os_mutex_unlock(&cluster->lock);
}
