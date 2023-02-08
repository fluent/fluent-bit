/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _THREAD_MANAGER_H
#define _THREAD_MANAGER_H

#include "bh_common.h"
#include "bh_log.h"
#include "wasm_export.h"
#include "../interpreter/wasm.h"
#include "../common/wasm_runtime_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
typedef struct WASMDebugInstance WASMDebugInstance;
#endif

struct WASMCluster {
    struct WASMCluster *next;

    korp_mutex lock;
    bh_list exec_env_list;

    /* The aux stack of a module with shared memory will be
        divided into several segments. This array store the
        stack top of different segments */
    uint32 *stack_tops;
    /* Size of every stack segment */
    uint32 stack_size;
    /* Record which segments are occupied */
    bool *stack_segment_occupied;
#if WASM_ENABLE_DEBUG_INTERP != 0
    WASMDebugInstance *debug_inst;
#endif
};

void
wasm_cluster_set_max_thread_num(uint32 num);

bool
thread_manager_init();

void
thread_manager_destroy();

/* Create cluster */
WASMCluster *
wasm_cluster_create(WASMExecEnv *exec_env);

/* Destroy cluster */
void
wasm_cluster_destroy(WASMCluster *cluster);

/* Get the cluster of the current exec_env */
WASMCluster *
wasm_exec_env_get_cluster(WASMExecEnv *exec_env);

int32
wasm_cluster_create_thread(WASMExecEnv *exec_env,
                           wasm_module_inst_t module_inst,
                           void *(*thread_routine)(void *), void *arg);

int32
wasm_cluster_join_thread(WASMExecEnv *exec_env, void **ret_val);

int32
wasm_cluster_detach_thread(WASMExecEnv *exec_env);

int32
wasm_cluster_cancel_thread(WASMExecEnv *exec_env);

void
wasm_cluster_exit_thread(WASMExecEnv *exec_env, void *retval);

bool
wasm_cluster_register_destroy_callback(void (*callback)(WASMCluster *));

void
wasm_cluster_cancel_all_callbacks();

void
wasm_cluster_suspend_all(WASMCluster *cluster);

void
wasm_cluster_suspend_all_except_self(WASMCluster *cluster,
                                     WASMExecEnv *exec_env);

void
wasm_cluster_suspend_thread(WASMExecEnv *exec_env);

void
wasm_cluster_resume_thread(WASMExecEnv *exec_env);

void
wasm_cluster_resume_all(WASMCluster *cluster);

void
wasm_cluster_terminate_all(WASMCluster *cluster);

void
wasm_cluster_terminate_all_except_self(WASMCluster *cluster,
                                       WASMExecEnv *exec_env);

void
wams_cluster_wait_for_all(WASMCluster *cluster);

void
wasm_cluster_wait_for_all_except_self(WASMCluster *cluster,
                                      WASMExecEnv *exec_env);

bool
wasm_cluster_add_exec_env(WASMCluster *cluster, WASMExecEnv *exec_env);

bool
wasm_cluster_del_exec_env(WASMCluster *cluster, WASMExecEnv *exec_env);

WASMExecEnv *
wasm_clusters_search_exec_env(WASMModuleInstanceCommon *module_inst);

void
wasm_cluster_spread_exception(WASMExecEnv *exec_env);

WASMExecEnv *
wasm_cluster_spawn_exec_env(WASMExecEnv *exec_env);

void
wasm_cluster_destroy_spawned_exec_env(WASMExecEnv *exec_env);

void
wasm_cluster_spread_custom_data(WASMModuleInstanceCommon *module_inst,
                                void *custom_data);

#if WASM_ENABLE_DEBUG_INTERP != 0
#define WAMR_SIG_TRAP (5)
#define WAMR_SIG_STOP (19)
#define WAMR_SIG_TERM (15)
#define WAMR_SIG_SINGSTEP (0x1ff)

#define STATUS_RUNNING (0)
#define STATUS_STOP (1)
#define STATUS_EXIT (2)
#define STATUS_STEP (3)

#define IS_WAMR_TERM_SIG(signo) ((signo) == WAMR_SIG_TERM)

#define IS_WAMR_STOP_SIG(signo) \
    ((signo) == WAMR_SIG_STOP || (signo) == WAMR_SIG_TRAP)

struct WASMCurrentEnvStatus {
    uint64 signal_flag : 32;
    uint64 step_count : 16;
    uint64 running_status : 16;
};

WASMCurrentEnvStatus *
wasm_cluster_create_exenv_status();

void
wasm_cluster_destroy_exenv_status(WASMCurrentEnvStatus *status);

void
wasm_cluster_send_signal_all(WASMCluster *cluster, uint32 signo);

void
wasm_cluster_thread_stopped(WASMExecEnv *exec_env);

void
wasm_cluster_thread_waiting_run(WASMExecEnv *exec_env);

void
wasm_cluster_wait_thread_status(WASMExecEnv *exec_env, uint32 *status);

void
wasm_cluster_thread_exited(WASMExecEnv *exec_env);

void
wasm_cluster_thread_continue(WASMExecEnv *exec_env);

void
wasm_cluster_thread_send_signal(WASMExecEnv *exec_env, uint32 signo);

void
wasm_cluster_thread_step(WASMExecEnv *exec_env);

void
wasm_cluster_set_debug_inst(WASMCluster *cluster, WASMDebugInstance *inst);

#endif /* end of WASM_ENABLE_DEBUG_INTERP != 0 */

#ifdef __cplusplus
}
#endif

#endif /* end of _THREAD_MANAGER_H */
