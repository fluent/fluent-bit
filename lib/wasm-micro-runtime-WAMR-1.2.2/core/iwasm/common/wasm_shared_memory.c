/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_log.h"
#include "wasm_shared_memory.h"
#if WASM_ENABLE_THREAD_MGR != 0
#include "../libraries/thread-mgr/thread_manager.h"
#endif

static bh_list shared_memory_list_head;
static bh_list *const shared_memory_list = &shared_memory_list_head;
static korp_mutex shared_memory_list_lock;

/* clang-format off */
enum {
    S_WAITING,
    S_NOTIFIED
};
/* clang-format on */

typedef struct AtomicWaitInfo {
    bh_list wait_list_head;
    bh_list *wait_list;
    /* WARNING: insert to the list allowed only in acquire_wait_info
       otherwise there will be data race as described in PR #2016 */
} AtomicWaitInfo;

typedef struct AtomicWaitNode {
    bh_list_link l;
    uint8 status;
    korp_cond wait_cond;
} AtomicWaitNode;

/* Atomic wait map */
static HashMap *wait_map;

static uint32
wait_address_hash(void *address);

static bool
wait_address_equal(void *h1, void *h2);

static void
destroy_wait_info(void *wait_info);

bool
wasm_shared_memory_init()
{
    if (os_mutex_init(&shared_memory_list_lock) != 0)
        return false;

    /* wait map not exists, create new map */
    if (!(wait_map = bh_hash_map_create(32, true, (HashFunc)wait_address_hash,
                                        (KeyEqualFunc)wait_address_equal, NULL,
                                        destroy_wait_info))) {
        os_mutex_destroy(&shared_memory_list_lock);
        return false;
    }

    return true;
}

void
wasm_shared_memory_destroy()
{
    bh_hash_map_destroy(wait_map);
    os_mutex_destroy(&shared_memory_list_lock);
}

static WASMSharedMemNode *
search_module(WASMModuleCommon *module)
{
    WASMSharedMemNode *node;

    os_mutex_lock(&shared_memory_list_lock);
    node = bh_list_first_elem(shared_memory_list);

    while (node) {
        if (module == node->module) {
            os_mutex_unlock(&shared_memory_list_lock);
            return node;
        }
        node = bh_list_elem_next(node);
    }

    os_mutex_unlock(&shared_memory_list_lock);
    return NULL;
}

WASMSharedMemNode *
wasm_module_get_shared_memory(WASMModuleCommon *module)
{
    return search_module(module);
}

int32
shared_memory_inc_reference(WASMModuleCommon *module)
{
    WASMSharedMemNode *node = search_module(module);
    uint32 ref_count = -1;
    if (node) {
        os_mutex_lock(&node->lock);
        ref_count = ++node->ref_count;
        os_mutex_unlock(&node->lock);
    }
    return ref_count;
}

int32
shared_memory_dec_reference(WASMModuleCommon *module)
{
    WASMSharedMemNode *node = search_module(module);
    uint32 ref_count = 0;
    if (node) {
        os_mutex_lock(&node->lock);
        ref_count = --node->ref_count;
        os_mutex_unlock(&node->lock);
        if (ref_count == 0) {
            os_mutex_lock(&shared_memory_list_lock);
            bh_list_remove(shared_memory_list, node);
            os_mutex_unlock(&shared_memory_list_lock);

            os_mutex_destroy(&node->shared_mem_lock);
            os_mutex_destroy(&node->lock);
            wasm_runtime_free(node);
        }
        return ref_count;
    }

    return -1;
}

WASMMemoryInstanceCommon *
shared_memory_get_memory_inst(WASMSharedMemNode *node)
{
    return node->memory_inst;
}

WASMSharedMemNode *
shared_memory_set_memory_inst(WASMModuleCommon *module,
                              WASMMemoryInstanceCommon *memory)
{
    WASMSharedMemNode *node;
    bh_list_status ret;

    if (!(node = wasm_runtime_malloc(sizeof(WASMSharedMemNode))))
        return NULL;

    node->module = module;
    node->memory_inst = memory;
    node->ref_count = 1;

    if (os_mutex_init(&node->shared_mem_lock) != 0) {
        wasm_runtime_free(node);
        return NULL;
    }

    if (os_mutex_init(&node->lock) != 0) {
        os_mutex_destroy(&node->shared_mem_lock);
        wasm_runtime_free(node);
        return NULL;
    }

    os_mutex_lock(&shared_memory_list_lock);
    ret = bh_list_insert(shared_memory_list, node);
    bh_assert(ret == BH_LIST_SUCCESS);
    os_mutex_unlock(&shared_memory_list_lock);

    (void)ret;
    return node;
}

/* Atomics wait && notify APIs */
static uint32
wait_address_hash(void *address)
{
    return (uint32)(uintptr_t)address;
}

static bool
wait_address_equal(void *h1, void *h2)
{
    return h1 == h2 ? true : false;
}

static bool
is_wait_node_exists(bh_list *wait_list, AtomicWaitNode *node)
{
    AtomicWaitNode *curr;
    curr = bh_list_first_elem(wait_list);

    while (curr) {
        if (curr == node) {
            return true;
        }
        curr = bh_list_elem_next(curr);
    }

    return false;
}

static uint32
notify_wait_list(bh_list *wait_list, uint32 count)
{
    AtomicWaitNode *node, *next;
    uint32 i, notify_count = count;

    if (count > wait_list->len)
        notify_count = wait_list->len;

    node = bh_list_first_elem(wait_list);
    if (!node)
        return 0;

    for (i = 0; i < notify_count; i++) {
        bh_assert(node);
        next = bh_list_elem_next(node);

        node->status = S_NOTIFIED;
        /* wakeup */
        os_cond_signal(&node->wait_cond);

        node = next;
    }

    return notify_count;
}

static AtomicWaitInfo *
acquire_wait_info(void *address, AtomicWaitNode *wait_node)
{
    AtomicWaitInfo *wait_info = NULL;
    bh_list_status ret;

    if (address)
        wait_info = (AtomicWaitInfo *)bh_hash_map_find(wait_map, address);

    if (!wait_node) {
        return wait_info;
    }

    /* No wait info on this address, create new info */
    if (!wait_info) {
        if (!(wait_info = (AtomicWaitInfo *)wasm_runtime_malloc(
                  sizeof(AtomicWaitInfo)))) {
            return NULL;
        }
        memset(wait_info, 0, sizeof(AtomicWaitInfo));

        /* init wait list */
        wait_info->wait_list = &wait_info->wait_list_head;
        ret = bh_list_init(wait_info->wait_list);
        bh_assert(ret == BH_LIST_SUCCESS);
        (void)ret;

        if (!bh_hash_map_insert(wait_map, address, (void *)wait_info)) {
            wasm_runtime_free(wait_info);
            return NULL;
        }
    }

    ret = bh_list_insert(wait_info->wait_list, wait_node);
    bh_assert(ret == BH_LIST_SUCCESS);
    (void)ret;

    return wait_info;
}

static void
destroy_wait_info(void *wait_info)
{
    AtomicWaitNode *node, *next;

    if (wait_info) {

        node = bh_list_first_elem(((AtomicWaitInfo *)wait_info)->wait_list);

        while (node) {
            next = bh_list_elem_next(node);
            os_cond_destroy(&node->wait_cond);
            wasm_runtime_free(node);
            node = next;
        }

        wasm_runtime_free(wait_info);
    }
}

static void
map_try_release_wait_info(HashMap *wait_map_, AtomicWaitInfo *wait_info,
                          void *address)
{
    if (wait_info->wait_list->len > 0) {
        return;
    }

    bh_hash_map_remove(wait_map_, address, NULL, NULL);
    destroy_wait_info(wait_info);
}

uint32
wasm_runtime_atomic_wait(WASMModuleInstanceCommon *module, void *address,
                         uint64 expect, int64 timeout, bool wait64)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module;
    AtomicWaitInfo *wait_info;
    AtomicWaitNode *wait_node;
    WASMSharedMemNode *node;
#if WASM_ENABLE_THREAD_MGR != 0
    WASMExecEnv *exec_env;
#endif
    uint64 timeout_left, timeout_wait, timeout_1sec;
    bool check_ret, is_timeout, no_wait;

    bh_assert(module->module_type == Wasm_Module_Bytecode
              || module->module_type == Wasm_Module_AoT);

    if (wasm_copy_exception(module_inst, NULL)) {
        return -1;
    }

    /* Currently we have only one memory instance */
    if (!module_inst->memories[0]->is_shared) {
        wasm_runtime_set_exception(module, "expected shared memory");
        return -1;
    }

    if ((uint8 *)address < module_inst->memories[0]->memory_data
        || (uint8 *)address + (wait64 ? 8 : 4)
               > module_inst->memories[0]->memory_data_end) {
        wasm_runtime_set_exception(module, "out of bounds memory access");
        return -1;
    }

#if WASM_ENABLE_THREAD_MGR != 0
    exec_env =
        wasm_clusters_search_exec_env((WASMModuleInstanceCommon *)module_inst);
    bh_assert(exec_env);
#endif

    node = search_module((WASMModuleCommon *)module_inst->module);
    bh_assert(node);

    /* Lock the shared_mem_lock for the whole atomic wait process,
       and use it to os_cond_reltimedwait */
    os_mutex_lock(&node->shared_mem_lock);

    no_wait = (!wait64 && *(uint32 *)address != (uint32)expect)
              || (wait64 && *(uint64 *)address != expect);

    if (no_wait) {
        os_mutex_unlock(&node->shared_mem_lock);
        return 1;
    }

    if (!(wait_node = wasm_runtime_malloc(sizeof(AtomicWaitNode)))) {
        os_mutex_unlock(&node->shared_mem_lock);
        wasm_runtime_set_exception(module, "failed to create wait node");
        return -1;
    }
    memset(wait_node, 0, sizeof(AtomicWaitNode));

    if (0 != os_cond_init(&wait_node->wait_cond)) {
        os_mutex_unlock(&node->shared_mem_lock);
        wasm_runtime_free(wait_node);
        wasm_runtime_set_exception(module, "failed to init wait cond");
        return -1;
    }

    wait_node->status = S_WAITING;

    /* Acquire the wait info, create new one if not exists */
    wait_info = acquire_wait_info(address, wait_node);

    if (!wait_info) {
        os_mutex_unlock(&node->shared_mem_lock);
        os_cond_destroy(&wait_node->wait_cond);
        wasm_runtime_free(wait_node);
        wasm_runtime_set_exception(module, "failed to acquire wait_info");
        return -1;
    }

    /* unit of timeout is nsec, convert it to usec */
    timeout_left = (uint64)timeout / 1000;
    timeout_1sec = (uint64)1e6;

    while (1) {
        if (timeout < 0) {
            /* wait forever until it is notified or terminatied
               here we keep waiting and checking every second */
            os_cond_reltimedwait(&wait_node->wait_cond, &node->shared_mem_lock,
                                 (uint64)timeout_1sec);
            if (wait_node->status == S_NOTIFIED /* notified by atomic.notify */
#if WASM_ENABLE_THREAD_MGR != 0
                /* terminated by other thread */
                || wasm_cluster_is_thread_terminated(exec_env)
#endif
            ) {
                break;
            }
        }
        else {
            timeout_wait =
                timeout_left < timeout_1sec ? timeout_left : timeout_1sec;
            os_cond_reltimedwait(&wait_node->wait_cond, &node->shared_mem_lock,
                                 timeout_wait);
            if (wait_node->status == S_NOTIFIED /* notified by atomic.notify */
                || timeout_left <= timeout_wait /* time out */
#if WASM_ENABLE_THREAD_MGR != 0
                /* terminated by other thread */
                || wasm_cluster_is_thread_terminated(exec_env)
#endif
            ) {
                break;
            }
            timeout_left -= timeout_wait;
        }
    }

    is_timeout = wait_node->status == S_WAITING ? true : false;

    check_ret = is_wait_node_exists(wait_info->wait_list, wait_node);
    bh_assert(check_ret);
    (void)check_ret;

    /* Remove wait node from wait list */
    bh_list_remove(wait_info->wait_list, wait_node);
    os_cond_destroy(&wait_node->wait_cond);
    wasm_runtime_free(wait_node);

    /* Release wait info if no wait nodes are attached */
    map_try_release_wait_info(wait_map, wait_info, address);

    os_mutex_unlock(&node->shared_mem_lock);

    return is_timeout ? 2 : 0;
}

uint32
wasm_runtime_atomic_notify(WASMModuleInstanceCommon *module, void *address,
                           uint32 count)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module;
    uint32 notify_result;
    AtomicWaitInfo *wait_info;
    WASMSharedMemNode *node;
    bool out_of_bounds;

    bh_assert(module->module_type == Wasm_Module_Bytecode
              || module->module_type == Wasm_Module_AoT);

    out_of_bounds =
        ((uint8 *)address < module_inst->memories[0]->memory_data
         || (uint8 *)address + 4 > module_inst->memories[0]->memory_data_end);

    if (out_of_bounds) {
        wasm_runtime_set_exception(module, "out of bounds memory access");
        return -1;
    }

    /* Currently we have only one memory instance */
    if (!module_inst->memories[0]->is_shared) {
        /* Always return 0 for ushared linear memory since there is
           no way to create a waiter on it */
        return 0;
    }

    node = search_module((WASMModuleCommon *)module_inst->module);
    bh_assert(node);

    /* Lock the shared_mem_lock for the whole atomic notify process,
       and use it to os_cond_signal */
    os_mutex_lock(&node->shared_mem_lock);

    wait_info = acquire_wait_info(address, NULL);

    /* Nobody wait on this address */
    if (!wait_info) {
        os_mutex_unlock(&node->shared_mem_lock);
        return 0;
    }

    /* Notify each wait node in the wait list */
    notify_result = notify_wait_list(wait_info->wait_list, count);

    os_mutex_unlock(&node->shared_mem_lock);

    return notify_result;
}
