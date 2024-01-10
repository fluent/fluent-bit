/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "debug_engine.h"
#include "gdbserver.h"
#include "handler.h"
#include "bh_platform.h"
#include "wasm_interp.h"
#include "wasm_opcode.h"
#include "wasm_runtime.h"

static const uint8 break_instr[] = { DEBUG_OP_BREAK };

typedef struct WASMDebugEngine {
    struct WASMDebugEngine *next;
    WASMDebugControlThread *control_thread;
    char ip_addr[128];
    int32 process_base_port;
    bh_list debug_instance_list;
    korp_mutex instance_list_lock;
} WASMDebugEngine;

void
on_thread_stop_event(WASMDebugInstance *debug_inst, WASMExecEnv *exec_env)
{
    os_mutex_lock(&debug_inst->wait_lock);
    debug_inst->stopped_thread = exec_env;

    if (debug_inst->current_state == DBG_LAUNCHING) {
        /* In launching phase, send a signal so that handle_threadstop_request
         * can be woken up */
        os_cond_signal(&debug_inst->wait_cond);
    }
    os_mutex_unlock(&debug_inst->wait_lock);
}

void
on_thread_exit_event(WASMDebugInstance *debug_inst, WASMExecEnv *exec_env)
{
    os_mutex_lock(&debug_inst->wait_lock);

    /* DBG_LAUNCHING: exit when debugger detached,
     * DBG_ERROR: exit when debugger error */
    if (debug_inst->current_state != DBG_LAUNCHING
        && debug_inst->current_state != DBG_ERROR) {
        /* only when exit normally the debugger thread will participate in
         * teardown phase */
        debug_inst->stopped_thread = exec_env;
    }

    os_mutex_unlock(&debug_inst->wait_lock);
}

static WASMDebugEngine *g_debug_engine;

static uint32 current_instance_id = 1;

static uint32
allocate_instance_id()
{
    uint32 id;

    bh_assert(g_debug_engine);

    os_mutex_lock(&g_debug_engine->instance_list_lock);
    id = current_instance_id++;
    os_mutex_unlock(&g_debug_engine->instance_list_lock);

    return id;
}

static bool
is_thread_running(WASMDebugControlThread *control_thread)
{
    return control_thread->status == RUNNING;
}

static bool
is_thread_stopped(WASMDebugControlThread *control_thread)
{
    return control_thread->status == STOPPED;
}

static bool
is_thread_detached(WASMDebugControlThread *control_thread)
{
    return control_thread->status == DETACHED;
}

static void *
control_thread_routine(void *arg)
{
    WASMDebugInstance *debug_inst = (WASMDebugInstance *)arg;
    WASMDebugControlThread *control_thread = NULL;

    control_thread = debug_inst->control_thread;
    bh_assert(control_thread);

    os_mutex_lock(&debug_inst->wait_lock);

    control_thread->status = RUNNING;

    debug_inst->id = allocate_instance_id();

    control_thread->debug_engine = g_debug_engine;
    control_thread->debug_instance = debug_inst;
    bh_strcpy_s(control_thread->ip_addr, sizeof(control_thread->ip_addr),
                g_debug_engine->ip_addr);
    if (control_thread->port == -1) {
        control_thread->port =
            (g_debug_engine->process_base_port == 0)
                ? 0
                : g_debug_engine->process_base_port + debug_inst->id - 1;
    }

    LOG_WARNING("control thread of debug object %p start\n", debug_inst);

    control_thread->server =
        wasm_create_gdbserver(control_thread->ip_addr, &control_thread->port);

    if (!control_thread->server) {
        LOG_ERROR("Failed to create debug server\n");
        control_thread->port = 0;
        os_cond_signal(&debug_inst->wait_cond);
        os_mutex_unlock(&debug_inst->wait_lock);
        return NULL;
    }

    control_thread->server->thread = control_thread;

    /*
     * wasm gdbserver created, the execution thread
     *  doesn't need to wait for the debugger connection,
     *  so we wake up the execution thread before listen
     */
    os_cond_signal(&debug_inst->wait_cond);
    os_mutex_unlock(&debug_inst->wait_lock);

    if (!wasm_gdbserver_listen(control_thread->server)) {
        LOG_ERROR("Failed while listening for debugger\n");
        goto fail;
    }

    /* outer infinite loop: try to connect with the debugger */
    while (true) {
        /* wait lldb client to connect */
        if (!wasm_gdbserver_accept(control_thread->server)) {
            LOG_ERROR("Failed while accepting debugger connection\n");
            goto fail;
        }

        control_thread->status = RUNNING;
        /* when reattached, send signal */
        wasm_cluster_send_signal_all(debug_inst->cluster, WAMR_SIG_SINGSTEP);

        /* inner infinite loop: keep serving until detach */
        while (true) {
            os_mutex_lock(&control_thread->wait_lock);
            if (is_thread_running(control_thread)) {
                /* send thread stop reply */
                if (debug_inst->stopped_thread
                    && debug_inst->current_state == APP_RUNNING) {
                    uint32 status;
                    korp_tid tid;

                    status = (uint32)debug_inst->stopped_thread->current_status
                                 ->signal_flag;
                    tid = debug_inst->stopped_thread->handle;

                    if (debug_inst->stopped_thread->current_status
                            ->running_status
                        == STATUS_EXIT) {
                        /* If the thread exits, report "W00" if it's the last
                         * thread in the cluster, otherwise ignore this event */
                        status = 0;

                        /* By design, all the other threads should have been
                         * stopped at this moment, so it is safe to access the
                         * exec_env_list.len without lock */
                        if (debug_inst->cluster->exec_env_list.len != 1) {
                            debug_inst->stopped_thread = NULL;
                            /* The exiting thread may wait for the signal */
                            os_cond_signal(&debug_inst->wait_cond);
                            os_mutex_unlock(&control_thread->wait_lock);
                            continue;
                        }
                    }

                    wasm_debug_instance_set_cur_thread(
                        debug_inst, debug_inst->stopped_thread->handle);

                    send_thread_stop_status(control_thread->server, status,
                                            tid);

                    debug_inst->current_state = APP_STOPPED;
                    debug_inst->stopped_thread = NULL;

                    if (status == 0) {
                        /* The exiting thread may wait for the signal */
                        os_cond_signal(&debug_inst->wait_cond);
                    }
                }

                /* Processing incoming requests */
                if (!wasm_gdbserver_handle_packet(control_thread->server)) {
                    control_thread->status = STOPPED;
                    LOG_ERROR("An error occurs when handling a packet\n");
                    os_mutex_unlock(&control_thread->wait_lock);
                    goto fail;
                }
            }
            else if (is_thread_detached(control_thread)) {
                os_mutex_unlock(&control_thread->wait_lock);
                break;
            }
            else if (is_thread_stopped(control_thread)) {
                os_mutex_unlock(&control_thread->wait_lock);
                return NULL;
            }
            os_mutex_unlock(&control_thread->wait_lock);
        }
    }
fail:
    wasm_debug_instance_on_failure(debug_inst);
    LOG_VERBOSE("control thread of debug object [%p] stopped with failure\n",
                debug_inst);
    return NULL;
}

static WASMDebugControlThread *
wasm_debug_control_thread_create(WASMDebugInstance *debug_instance, int32 port)
{
    WASMDebugControlThread *control_thread;

    if (!(control_thread =
              wasm_runtime_malloc(sizeof(WASMDebugControlThread)))) {
        LOG_ERROR("WASM Debug Engine error: failed to allocate memory");
        return NULL;
    }
    memset(control_thread, 0, sizeof(WASMDebugControlThread));
    control_thread->port = port;

    if (os_mutex_init(&control_thread->wait_lock) != 0)
        goto fail;

    debug_instance->control_thread = control_thread;

    os_mutex_lock(&debug_instance->wait_lock);

    if (0
        != os_thread_create(&control_thread->tid, control_thread_routine,
                            debug_instance, APP_THREAD_STACK_SIZE_DEFAULT)) {
        os_mutex_unlock(&debug_instance->wait_lock);
        goto fail1;
    }

    /* wait until the debug control thread ready */
    os_cond_wait(&debug_instance->wait_cond, &debug_instance->wait_lock);
    os_mutex_unlock(&debug_instance->wait_lock);
    if (!control_thread->server) {
        os_thread_join(control_thread->tid, NULL);
        goto fail1;
    }

    os_mutex_lock(&g_debug_engine->instance_list_lock);
    /* create control thread success, append debug instance to debug engine */
    bh_list_insert(&g_debug_engine->debug_instance_list, debug_instance);
    os_mutex_unlock(&g_debug_engine->instance_list_lock);

    /* If we set WAMR_SIG_STOP here, the VSCode debugger adaptor will raise an
     * exception in the UI. We use WAMR_SIG_SINGSTEP to avoid this exception for
     * better user experience */
    wasm_cluster_send_signal_all(debug_instance->cluster, WAMR_SIG_SINGSTEP);

    return control_thread;

fail1:
    os_mutex_destroy(&control_thread->wait_lock);
fail:
    wasm_runtime_free(control_thread);
    return NULL;
}

static void
wasm_debug_control_thread_destroy(WASMDebugInstance *debug_instance)
{
    WASMDebugControlThread *control_thread = debug_instance->control_thread;

    LOG_VERBOSE("stopping control thread of debug object [%p]\n",
                debug_instance);
    control_thread->status = STOPPED;
    os_mutex_lock(&control_thread->wait_lock);
    wasm_close_gdbserver(control_thread->server);
    os_mutex_unlock(&control_thread->wait_lock);
    os_thread_join(control_thread->tid, NULL);
    wasm_runtime_free(control_thread->server);

    os_mutex_destroy(&control_thread->wait_lock);
    wasm_runtime_free(control_thread);
}

static WASMDebugEngine *
wasm_debug_engine_create()
{
    WASMDebugEngine *engine;

    if (!(engine = wasm_runtime_malloc(sizeof(WASMDebugEngine)))) {
        LOG_ERROR("WASM Debug Engine error: failed to allocate memory");
        return NULL;
    }
    memset(engine, 0, sizeof(WASMDebugEngine));

    if (os_mutex_init(&engine->instance_list_lock) != 0) {
        wasm_runtime_free(engine);
        LOG_ERROR("WASM Debug Engine error: failed to init mutex");
        return NULL;
    }

    /* reset current instance id */
    current_instance_id = 1;

    bh_list_init(&engine->debug_instance_list);
    return engine;
}

void
wasm_debug_engine_destroy()
{
    if (g_debug_engine) {
        wasm_debug_handler_deinit();
        os_mutex_destroy(&g_debug_engine->instance_list_lock);
        wasm_runtime_free(g_debug_engine);
        g_debug_engine = NULL;
    }
}

bool
wasm_debug_engine_init(char *ip_addr, int32 process_port)
{
    if (wasm_debug_handler_init() != 0) {
        return false;
    }

    if (g_debug_engine == NULL) {
        g_debug_engine = wasm_debug_engine_create();
    }

    if (g_debug_engine) {
        g_debug_engine->process_base_port =
            (process_port > 0) ? process_port : 0;
        if (ip_addr)
            snprintf(g_debug_engine->ip_addr, sizeof(g_debug_engine->ip_addr),
                     "%s", ip_addr);
        else
            snprintf(g_debug_engine->ip_addr, sizeof(g_debug_engine->ip_addr),
                     "%s", "127.0.0.1");
    }
    else {
        wasm_debug_handler_deinit();
    }

    return g_debug_engine != NULL ? true : false;
}

/* A debug Instance is a debug "process" in gdb remote protocol
   and bound to a runtime cluster */
WASMDebugInstance *
wasm_debug_instance_create(WASMCluster *cluster, int32 port)
{
    WASMDebugInstance *instance;
    WASMExecEnv *exec_env = NULL;
    wasm_module_inst_t module_inst = NULL;

    if (!g_debug_engine) {
        return NULL;
    }

    if (!(instance = wasm_runtime_malloc(sizeof(WASMDebugInstance)))) {
        LOG_ERROR("WASM Debug Engine error: failed to allocate memory");
        return NULL;
    }
    memset(instance, 0, sizeof(WASMDebugInstance));

    if (os_mutex_init(&instance->wait_lock) != 0) {
        goto fail1;
    }

    if (os_cond_init(&instance->wait_cond) != 0) {
        goto fail2;
    }

    bh_list_init(&instance->break_point_list);
    bh_list_init(&instance->watch_point_list_read);
    bh_list_init(&instance->watch_point_list_write);

    instance->cluster = cluster;
    exec_env = bh_list_first_elem(&cluster->exec_env_list);
    bh_assert(exec_env);

    instance->current_tid = exec_env->handle;

    module_inst = wasm_runtime_get_module_inst(exec_env);
    bh_assert(module_inst);

    /* Allocate linear memory for evaluating expressions during debugging. If
     * the allocation failed, the debugger will not be able to evaluate
     * expressions */
    instance->exec_mem_info.size = DEBUG_EXECUTION_MEMORY_SIZE;
    instance->exec_mem_info.start_offset = wasm_runtime_module_malloc(
        module_inst, instance->exec_mem_info.size, NULL);
    if (instance->exec_mem_info.start_offset == 0) {
        LOG_WARNING(
            "WASM Debug Engine warning: failed to allocate linear memory for "
            "execution. \n"
            "Will not be able to evaluate expressions during "
            "debugging");
    }
    instance->exec_mem_info.current_pos = instance->exec_mem_info.start_offset;

    if (!wasm_debug_control_thread_create(instance, port)) {
        LOG_ERROR("WASM Debug Engine error: failed to create control thread");
        goto fail3;
    }

    wasm_cluster_set_debug_inst(cluster, instance);

    return instance;

fail3:
    os_cond_destroy(&instance->wait_cond);
fail2:
    os_mutex_destroy(&instance->wait_lock);
fail1:
    wasm_runtime_free(instance);

    return NULL;
}

static void
wasm_debug_instance_destroy_breakpoints(WASMDebugInstance *instance)
{
    WASMDebugBreakPoint *breakpoint, *next_bp;

    breakpoint = bh_list_first_elem(&instance->break_point_list);
    while (breakpoint) {
        next_bp = bh_list_elem_next(breakpoint);

        bh_list_remove(&instance->break_point_list, breakpoint);
        wasm_runtime_free(breakpoint);

        breakpoint = next_bp;
    }
}

static void
wasm_debug_instance_destroy_watchpoints(WASMDebugInstance *instance,
                                        bh_list *watchpoints)
{
    WASMDebugWatchPoint *watchpoint, *next;

    watchpoint = bh_list_first_elem(watchpoints);
    while (watchpoint) {
        next = bh_list_elem_next(watchpoint);

        bh_list_remove(watchpoints, watchpoint);
        wasm_runtime_free(watchpoint);

        watchpoint = next;
    }
}

void
wasm_debug_instance_destroy(WASMCluster *cluster)
{
    WASMDebugInstance *instance = NULL;

    if (!g_debug_engine) {
        return;
    }

    instance = cluster->debug_inst;
    if (instance) {
        /* destroy control thread */
        wasm_debug_control_thread_destroy(instance);

        os_mutex_lock(&g_debug_engine->instance_list_lock);
        bh_list_remove(&g_debug_engine->debug_instance_list, instance);
        os_mutex_unlock(&g_debug_engine->instance_list_lock);

        /* destroy all breakpoints */
        wasm_debug_instance_destroy_breakpoints(instance);
        wasm_debug_instance_destroy_watchpoints(
            instance, &instance->watch_point_list_read);
        wasm_debug_instance_destroy_watchpoints(
            instance, &instance->watch_point_list_write);

        os_mutex_destroy(&instance->wait_lock);
        os_cond_destroy(&instance->wait_cond);

        wasm_runtime_free(instance);
        cluster->debug_inst = NULL;
    }
}

WASMExecEnv *
wasm_debug_instance_get_current_env(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env = NULL;

    if (instance) {
        exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
        while (exec_env) {
            if (exec_env->handle == instance->current_tid)
                break;
            exec_env = bh_list_elem_next(exec_env);
        }
    }
    return exec_env;
}

#if WASM_ENABLE_LIBC_WASI != 0
bool
wasm_debug_instance_get_current_object_name(WASMDebugInstance *instance,
                                            char name_buffer[], uint32 len)
{
    WASMExecEnv *exec_env;
    WASIArguments *wasi_args;
    WASMModuleInstance *module_inst;

    if (!instance)
        return false;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;
    wasi_args = &module_inst->module->wasi_args;
    if (wasi_args && wasi_args->argc > 0) {
        char *argv_name = wasi_args->argv[0];
        uint32 name_len = (uint32)strlen(argv_name);

        printf("the module name is %s\n", argv_name);
        if (len - 1 >= name_len)
            bh_strcpy_s(name_buffer, len, argv_name);
        else
            bh_strcpy_s(name_buffer, len, argv_name + (name_len + 1 - len));
        return true;
    }
    return false;
}
#endif

uint64
wasm_debug_instance_get_pid(WASMDebugInstance *instance)
{
    if (instance != NULL) {
        return (uint64)instance->id;
    }
    return (uint64)0;
}

korp_tid
wasm_debug_instance_get_tid(WASMDebugInstance *instance)
{
    if (instance != NULL) {
        return instance->current_tid;
    }
    return (korp_tid)(uintptr_t)0;
}

uint32
wasm_debug_instance_get_tids(WASMDebugInstance *instance, korp_tid tids[],
                             uint32 len)
{
    WASMExecEnv *exec_env;
    uint32 i = 0, threads_num = 0;

    if (!instance)
        return 0;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    while (exec_env && i < len) {
        /* Some threads may not be ready */
        if (exec_env->handle != 0) {
            tids[i++] = exec_env->handle;
            threads_num++;
        }
        exec_env = bh_list_elem_next(exec_env);
    }
    LOG_VERBOSE("find %d tids\n", threads_num);
    return threads_num;
}

uint32
wasm_debug_instance_get_thread_status(WASMDebugInstance *instance, korp_tid tid)
{
    WASMExecEnv *exec_env = NULL;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    while (exec_env) {
        if (exec_env->handle == tid) {
            return (uint32)exec_env->current_status->signal_flag;
        }
        exec_env = bh_list_elem_next(exec_env);
    }

    return 0;
}

void
wasm_debug_instance_set_cur_thread(WASMDebugInstance *instance, korp_tid tid)
{
    instance->current_tid = tid;
}

uint64
wasm_debug_instance_get_pc(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return 0;

    exec_env = wasm_debug_instance_get_current_env(instance);
    if ((exec_env != NULL) && (exec_env->cur_frame != NULL)
        && (exec_env->cur_frame->ip != NULL)) {
        WASMModuleInstance *module_inst =
            (WASMModuleInstance *)exec_env->module_inst;
        return WASM_ADDR(
            WasmObj, instance->id,
            (exec_env->cur_frame->ip - module_inst->module->load_addr));
    }
    return 0;
}

uint64
wasm_debug_instance_get_load_addr(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return WASM_ADDR(WasmInvalid, 0, 0);

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (exec_env) {
        return WASM_ADDR(WasmObj, instance->id, 0);
    }

    return WASM_ADDR(WasmInvalid, 0, 0);
}

WASMDebugMemoryInfo *
wasm_debug_instance_get_memregion(WASMDebugInstance *instance, uint64 addr)
{
    WASMDebugMemoryInfo *mem_info;
    WASMExecEnv *exec_env;
    WASMModuleInstance *module_inst;
    WASMMemoryInstance *memory;
    uint32 num_bytes_per_page;
    uint32 linear_mem_size = 0;

    if (!instance)
        return NULL;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return NULL;

    if (!(mem_info = wasm_runtime_malloc(sizeof(WASMDebugMemoryInfo)))) {
        LOG_ERROR("WASM Debug Engine error: failed to allocate memory");
        return NULL;
    }
    memset(mem_info, 0, sizeof(WASMDebugMemoryInfo));
    mem_info->start = WASM_ADDR(WasmInvalid, 0, 0);
    mem_info->size = 0;
    mem_info->name[0] = '\0';
    mem_info->permisson[0] = '\0';

    module_inst = (WASMModuleInstance *)exec_env->module_inst;

    switch (WASM_ADDR_TYPE(addr)) {
        case WasmObj:
            if (WASM_ADDR_OFFSET(addr) < module_inst->module->load_size) {
                mem_info->start = WASM_ADDR(WasmObj, instance->id, 0);
                mem_info->size = module_inst->module->load_size;
                snprintf(mem_info->name, sizeof(mem_info->name), "%s",
                         "module");
                snprintf(mem_info->permisson, sizeof(mem_info->permisson), "%s",
                         "rx");
            }
            break;
        case WasmMemory:
        {
            memory = wasm_get_default_memory(module_inst);

            if (memory) {
                num_bytes_per_page = memory->num_bytes_per_page;
                linear_mem_size = num_bytes_per_page * memory->cur_page_count;
            }
            if (WASM_ADDR_OFFSET(addr) < linear_mem_size) {
                mem_info->start = WASM_ADDR(WasmMemory, instance->id, 0);
                mem_info->size = linear_mem_size;
                snprintf(mem_info->name, sizeof(mem_info->name), "%s",
                         "memory");
                snprintf(mem_info->permisson, sizeof(mem_info->permisson), "%s",
                         "rw");
            }
            break;
        }
        default:
            mem_info->start = WASM_ADDR(WasmInvalid, 0, 0);
            mem_info->size = 0;
    }
    return mem_info;
}

void
wasm_debug_instance_destroy_memregion(WASMDebugInstance *instance,
                                      WASMDebugMemoryInfo *mem_info)
{
    wasm_runtime_free(mem_info);
}

bool
wasm_debug_instance_get_obj_mem(WASMDebugInstance *instance, uint64 offset,
                                char *buf, uint64 *size)
{
    WASMExecEnv *exec_env;
    WASMModuleInstance *module_inst;
    WASMDebugBreakPoint *breakpoint;
    WASMFastOPCodeNode *fast_opcode;

    if (!instance)
        return false;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;

    if (offset + *size > module_inst->module->load_size) {
        LOG_VERBOSE("wasm_debug_instance_get_data_mem size over flow!\n");
        *size = module_inst->module->load_size >= offset
                    ? module_inst->module->load_size - offset
                    : 0;
    }

    bh_memcpy_s(buf, (uint32)*size, module_inst->module->load_addr + offset,
                (uint32)*size);

    breakpoint = bh_list_first_elem(&instance->break_point_list);
    while (breakpoint) {
        if (offset <= breakpoint->addr && breakpoint->addr < offset + *size) {
            bh_memcpy_s(buf + (breakpoint->addr - offset), sizeof(break_instr),
                        &breakpoint->orignal_data, sizeof(break_instr));
        }
        breakpoint = bh_list_elem_next(breakpoint);
    }

    fast_opcode = bh_list_first_elem(&module_inst->module->fast_opcode_list);
    while (fast_opcode) {
        if (offset <= fast_opcode->offset
            && fast_opcode->offset < offset + *size) {
            *(uint8 *)(buf + (fast_opcode->offset - offset)) =
                fast_opcode->orig_op;
        }
        fast_opcode = bh_list_elem_next(fast_opcode);
    }

    return true;
}

bool
wasm_debug_instance_get_linear_mem(WASMDebugInstance *instance, uint64 offset,
                                   char *buf, uint64 *size)
{
    WASMExecEnv *exec_env;
    WASMModuleInstance *module_inst;
    WASMMemoryInstance *memory;
    uint32 num_bytes_per_page;
    uint32 linear_mem_size;

    if (!instance)
        return false;

    exec_env = wasm_debug_instance_get_current_env(instance);
    if (!exec_env)
        return false;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;
    memory = wasm_get_default_memory(module_inst);
    if (memory) {
        num_bytes_per_page = memory->num_bytes_per_page;
        linear_mem_size = num_bytes_per_page * memory->cur_page_count;
        if (offset + *size > linear_mem_size) {
            LOG_VERBOSE("wasm_debug_instance_get_linear_mem size over flow!\n");
            *size = linear_mem_size >= offset ? linear_mem_size - offset : 0;
        }
        bh_memcpy_s(buf, (uint32)*size, memory->memory_data + offset,
                    (uint32)*size);
        return true;
    }
    return false;
}

bool
wasm_debug_instance_set_linear_mem(WASMDebugInstance *instance, uint64 offset,
                                   char *buf, uint64 *size)
{
    WASMExecEnv *exec_env;
    WASMModuleInstance *module_inst;
    WASMMemoryInstance *memory;
    uint32 num_bytes_per_page;
    uint32 linear_mem_size;

    if (!instance)
        return false;

    exec_env = wasm_debug_instance_get_current_env(instance);
    if (!exec_env)
        return false;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;
    memory = wasm_get_default_memory(module_inst);
    if (memory) {
        num_bytes_per_page = memory->num_bytes_per_page;
        linear_mem_size = num_bytes_per_page * memory->cur_page_count;
        if (offset + *size > linear_mem_size) {
            LOG_VERBOSE("wasm_debug_instance_get_linear_mem size over flow!\n");
            *size = linear_mem_size >= offset ? linear_mem_size - offset : 0;
        }
        bh_memcpy_s(memory->memory_data + offset, (uint32)*size, buf,
                    (uint32)*size);
        return true;
    }
    return false;
}

bool
wasm_debug_instance_get_mem(WASMDebugInstance *instance, uint64 addr, char *buf,
                            uint64 *size)
{
    switch (WASM_ADDR_TYPE(addr)) {
        case WasmMemory:
            return wasm_debug_instance_get_linear_mem(
                instance, WASM_ADDR_OFFSET(addr), buf, size);
            break;
        case WasmObj:
            return wasm_debug_instance_get_obj_mem(
                instance, WASM_ADDR_OFFSET(addr), buf, size);
            break;
        default:
            return false;
    }
}

bool
wasm_debug_instance_set_mem(WASMDebugInstance *instance, uint64 addr, char *buf,
                            uint64 *size)
{
    switch (WASM_ADDR_TYPE(addr)) {
        case WasmMemory:
            return wasm_debug_instance_set_linear_mem(
                instance, WASM_ADDR_OFFSET(addr), buf, size);
            break;
        case WasmObj:
        default:
            return false;
    }
}

WASMDebugInstance *
wasm_exec_env_get_instance(WASMExecEnv *exec_env)
{
    WASMDebugInstance *instance = NULL;

    if (!g_debug_engine) {
        return NULL;
    }

    os_mutex_lock(&g_debug_engine->instance_list_lock);
    instance = bh_list_first_elem(&g_debug_engine->debug_instance_list);
    while (instance) {
        if (instance->cluster == exec_env->cluster)
            break;
        instance = bh_list_elem_next(instance);
    }

    os_mutex_unlock(&g_debug_engine->instance_list_lock);
    return instance;
}

uint32
wasm_debug_instance_get_call_stack_pcs(WASMDebugInstance *instance,
                                       korp_tid tid, uint64 buf[], uint64 size)
{
    WASMExecEnv *exec_env;
    struct WASMInterpFrame *frame;
    uint32 i = 0;

    if (!instance)
        return 0;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    while (exec_env) {
        if (exec_env->handle == tid) {
            WASMModuleInstance *module_inst =
                (WASMModuleInstance *)exec_env->module_inst;
            frame = exec_env->cur_frame;
            while (frame && i < size) {
                if (frame->ip != NULL) {
                    buf[i++] =
                        WASM_ADDR(WasmObj, instance->id,
                                  (frame->ip - module_inst->module->load_addr));
                }
                frame = frame->prev_frame;
            }
            return i;
        }
        exec_env = bh_list_elem_next(exec_env);
    }
    return 0;
}

bool
wasm_debug_instance_add_breakpoint(WASMDebugInstance *instance, uint64 addr,
                                   uint64 length)
{
    WASMExecEnv *exec_env;
    WASMModuleInstance *module_inst;
    uint64 offset;

    if (!instance)
        return false;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;
    if (WASM_ADDR_TYPE(addr) != WasmObj)
        return false;

    offset = WASM_ADDR_OFFSET(addr);

    if (length >= sizeof(break_instr)) {
        if (offset + sizeof(break_instr) <= module_inst->module->load_size) {
            WASMDebugBreakPoint *breakpoint;
            if (!(breakpoint =
                      wasm_runtime_malloc(sizeof(WASMDebugBreakPoint)))) {
                LOG_ERROR("WASM Debug Engine error: failed to allocate memory");
                return false;
            }
            memset(breakpoint, 0, sizeof(WASMDebugBreakPoint));
            breakpoint->addr = offset;
            /* TODO: how to if more than one breakpoints are set
                     at the same addr? */
            bh_memcpy_s(&breakpoint->orignal_data, (uint32)sizeof(break_instr),
                        module_inst->module->load_addr + offset,
                        (uint32)sizeof(break_instr));

            bh_memcpy_s(module_inst->module->load_addr + offset,
                        (uint32)sizeof(break_instr), break_instr,
                        (uint32)sizeof(break_instr));

            bh_list_insert(&instance->break_point_list, breakpoint);
            return true;
        }
    }
    return false;
}

bool
wasm_debug_instance_remove_breakpoint(WASMDebugInstance *instance, uint64 addr,
                                      uint64 length)
{
    WASMExecEnv *exec_env;
    WASMModuleInstance *module_inst;
    uint64 offset;

    if (!instance)
        return false;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;

    if (WASM_ADDR_TYPE(addr) != WasmObj)
        return false;
    offset = WASM_ADDR_OFFSET(addr);

    if (length >= sizeof(break_instr)) {
        if (offset + sizeof(break_instr) <= module_inst->module->load_size) {
            WASMDebugBreakPoint *breakpoint =
                bh_list_first_elem(&instance->break_point_list);
            while (breakpoint) {
                WASMDebugBreakPoint *next_break = bh_list_elem_next(breakpoint);
                if (breakpoint->addr == offset) {
                    /* TODO: how to if more than one breakpoints are set
                       at the same addr? */
                    bh_memcpy_s(module_inst->module->load_addr + offset,
                                (uint32)sizeof(break_instr),
                                &breakpoint->orignal_data,
                                (uint32)sizeof(break_instr));
                    bh_list_remove(&instance->break_point_list, breakpoint);
                    wasm_runtime_free(breakpoint);
                }
                breakpoint = next_break;
            }
        }
    }
    return true;
}

static bool
add_watchpoint(bh_list *list, uint64 addr, uint64 length)
{
    WASMDebugWatchPoint *watchpoint;
    if (!(watchpoint = wasm_runtime_malloc(sizeof(WASMDebugWatchPoint)))) {
        LOG_ERROR("WASM Debug Engine error: failed to allocate memory for "
                  "watchpoint");
        return false;
    }
    memset(watchpoint, 0, sizeof(WASMDebugWatchPoint));
    watchpoint->addr = addr;
    watchpoint->length = length;
    bh_list_insert(list, watchpoint);
    return true;
}

static bool
remove_watchpoint(bh_list *list, uint64 addr, uint64 length)
{
    WASMDebugWatchPoint *watchpoint = bh_list_first_elem(list);
    while (watchpoint) {
        WASMDebugWatchPoint *next = bh_list_elem_next(watchpoint);
        if (watchpoint->addr == addr && watchpoint->length == length) {
            bh_list_remove(list, watchpoint);
            wasm_runtime_free(watchpoint);
        }
        watchpoint = next;
    }
    return true;
}

bool
wasm_debug_instance_watchpoint_write_add(WASMDebugInstance *instance,
                                         uint64 addr, uint64 length)
{
    return add_watchpoint(&instance->watch_point_list_write, addr, length);
}

bool
wasm_debug_instance_watchpoint_write_remove(WASMDebugInstance *instance,
                                            uint64 addr, uint64 length)
{
    return remove_watchpoint(&instance->watch_point_list_write, addr, length);
}

bool
wasm_debug_instance_watchpoint_read_add(WASMDebugInstance *instance,
                                        uint64 addr, uint64 length)
{
    return add_watchpoint(&instance->watch_point_list_read, addr, length);
}

bool
wasm_debug_instance_watchpoint_read_remove(WASMDebugInstance *instance,
                                           uint64 addr, uint64 length)
{
    return remove_watchpoint(&instance->watch_point_list_read, addr, length);
}

bool
wasm_debug_instance_on_failure(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return false;

    os_mutex_lock(&instance->wait_lock);
    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env) {
        os_mutex_unlock(&instance->wait_lock);
        return false;
    }

    if (instance->stopped_thread == NULL
        && instance->current_state == DBG_LAUNCHING) {
        /* if fail in start stage: may need wait for main thread to notify it */
        os_cond_wait(&instance->wait_cond, &instance->wait_lock);
    }
    instance->current_state = DBG_ERROR;
    instance->stopped_thread = NULL;

    /* terminate the wasm execution thread */
    while (exec_env) {
        /* Resume all threads so they can receive the TERM signal */
        os_mutex_lock(&exec_env->wait_lock);
        wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_TERM);
        exec_env->current_status->running_status = STATUS_RUNNING;
        os_cond_signal(&exec_env->wait_cond);
        os_mutex_unlock(&exec_env->wait_lock);
        exec_env = bh_list_elem_next(exec_env);
    }
    os_mutex_unlock(&instance->wait_lock);

    return true;
}

bool
wasm_debug_instance_continue(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return false;

    if (instance->current_state == APP_RUNNING) {
        LOG_VERBOSE("Already in running state, ignore continue request");
        return false;
    }

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    while (exec_env) {
        wasm_cluster_thread_continue(exec_env);
        exec_env = bh_list_elem_next(exec_env);
    }

    instance->current_state = APP_RUNNING;

    return true;
}

bool
wasm_debug_instance_interrupt_all_threads(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return false;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    while (exec_env) {
        wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_TRAP);
        exec_env = bh_list_elem_next(exec_env);
    }
    return true;
}

bool
wasm_debug_instance_detach(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return false;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    wasm_gdbserver_detach(instance->control_thread->server);

    while (exec_env) {
        if (instance->current_state == APP_STOPPED) {
            /* Resume all threads since remote debugger detached*/
            wasm_cluster_thread_continue(exec_env);
        }
        exec_env = bh_list_elem_next(exec_env);
    }

    /* relaunch, accept new debug connection */
    instance->current_state = DBG_LAUNCHING;
    instance->control_thread->status = DETACHED;
    instance->stopped_thread = NULL;

    return true;
}

bool
wasm_debug_instance_kill(WASMDebugInstance *instance)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return false;

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    while (exec_env) {
        wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_TERM);
        if (instance->current_state == APP_STOPPED) {
            /* Resume all threads so they can receive the TERM signal */
            os_mutex_lock(&exec_env->wait_lock);
            exec_env->current_status->running_status = STATUS_RUNNING;
            os_cond_signal(&exec_env->wait_cond);
            os_mutex_unlock(&exec_env->wait_lock);
        }
        exec_env = bh_list_elem_next(exec_env);
    }

    instance->current_state = APP_RUNNING;
    return true;
}

bool
wasm_debug_instance_singlestep(WASMDebugInstance *instance, korp_tid tid)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return false;

    if (instance->current_state == APP_RUNNING) {
        LOG_VERBOSE("Already in running state, ignore step request");
        return false;
    }

    exec_env = bh_list_first_elem(&instance->cluster->exec_env_list);
    if (!exec_env)
        return false;

    while (exec_env) {
        if (exec_env->handle == tid || tid == (korp_tid)(uintptr_t)~0LL) {
            wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_SINGSTEP);
            wasm_cluster_thread_step(exec_env);
        }
        exec_env = bh_list_elem_next(exec_env);
    }

    instance->current_state = APP_RUNNING;

    return true;
}

bool
wasm_debug_instance_get_local(WASMDebugInstance *instance, int32 frame_index,
                              int32 local_index, char buf[], int32 *size)
{
    WASMExecEnv *exec_env;
    struct WASMInterpFrame *frame;
    WASMFunctionInstance *cur_func;
    uint8 local_type = 0xFF;
    uint32 local_offset;
    int32 param_count;
    int32 fi = 0;

    if (!instance)
        return false;

    exec_env = wasm_debug_instance_get_current_env(instance);
    if (!exec_env)
        return false;

    frame = exec_env->cur_frame;
    while (frame && fi++ != frame_index) {
        frame = frame->prev_frame;
    }

    if (!frame)
        return false;
    cur_func = frame->function;
    if (!cur_func)
        return false;

    param_count = cur_func->param_count;

    if (local_index >= param_count + cur_func->local_count)
        return false;

    local_offset = cur_func->local_offsets[local_index];
    if (local_index < param_count)
        local_type = cur_func->param_types[local_index];
    else if (local_index < cur_func->local_count + param_count)
        local_type = cur_func->local_types[local_index - param_count];

    switch (local_type) {
        case VALUE_TYPE_I32:
        case VALUE_TYPE_F32:
            *size = 4;
            bh_memcpy_s(buf, 4, (char *)(frame->lp + local_offset), 4);
            break;
        case VALUE_TYPE_I64:
        case VALUE_TYPE_F64:
            *size = 8;
            bh_memcpy_s(buf, 8, (char *)(frame->lp + local_offset), 8);
            break;
        default:
            *size = 0;
            break;
    }
    return true;
}

bool
wasm_debug_instance_get_global(WASMDebugInstance *instance, int32 frame_index,
                               int32 global_index, char buf[], int32 *size)
{
    WASMExecEnv *exec_env;
    struct WASMInterpFrame *frame;
    WASMModuleInstance *module_inst;
    WASMGlobalInstance *globals, *global;
    uint8 *global_addr;
    uint8 global_type = 0xFF;
    uint8 *global_data;
    int32 fi = 0;

    if (!instance)
        return false;

    exec_env = wasm_debug_instance_get_current_env(instance);
    if (!exec_env)
        return false;

    frame = exec_env->cur_frame;
    while (frame && fi++ != frame_index) {
        frame = frame->prev_frame;
    }

    if (!frame)
        return false;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;
    global_data = module_inst->global_data;
    globals = module_inst->e->globals;

    if ((global_index < 0)
        || ((uint32)global_index >= module_inst->e->global_count)) {
        return false;
    }
    global = globals + global_index;

#if WASM_ENABLE_MULTI_MODULE == 0
    global_addr = global_data + global->data_offset;
#else
    global_addr = global->import_global_inst
                      ? global->import_module_inst->global_data
                            + global->import_global_inst->data_offset
                      : global_data + global->data_offset;
#endif
    global_type = global->type;

    switch (global_type) {
        case VALUE_TYPE_I32:
        case VALUE_TYPE_F32:
            *size = 4;
            bh_memcpy_s(buf, 4, (char *)(global_addr), 4);
            break;
        case VALUE_TYPE_I64:
        case VALUE_TYPE_F64:
            *size = 8;
            bh_memcpy_s(buf, 8, (char *)(global_addr), 8);
            break;
        default:
            *size = 0;
            break;
    }
    return true;
}

uint64
wasm_debug_instance_mmap(WASMDebugInstance *instance, uint32 size,
                         int32 map_prot)
{
    WASMExecEnv *exec_env;
    uint32 offset = 0;
    (void)map_prot;

    if (!instance)
        return 0;

    exec_env = wasm_debug_instance_get_current_env(instance);
    if (!exec_env)
        return 0;

    if (instance->exec_mem_info.start_offset == 0) {
        return 0;
    }

    if ((uint64)instance->exec_mem_info.current_pos
            - instance->exec_mem_info.start_offset + size
        <= (uint64)instance->exec_mem_info.size) {
        offset = instance->exec_mem_info.current_pos;
        instance->exec_mem_info.current_pos += size;
    }

    if (offset == 0) {
        LOG_WARNING("the memory may be not enough for debug, try use larger "
                    "--heap-size");
        return 0;
    }

    return WASM_ADDR(WasmMemory, 0, offset);
}

bool
wasm_debug_instance_ummap(WASMDebugInstance *instance, uint64 addr)
{
    WASMExecEnv *exec_env;

    if (!instance)
        return false;

    exec_env = wasm_debug_instance_get_current_env(instance);
    if (!exec_env)
        return false;

    if (instance->exec_mem_info.start_offset == 0) {
        return false;
    }

    (void)addr;

    /* Currently we don't support to free the execution memory, simply return
     * true here */
    return true;
}
