/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _DEBUG_ENGINE_H
#define _DEBUG_ENGINE_H

#include "bh_list.h"
#include "gdbserver.h"
#include "thread_manager.h"

typedef enum WASMDebugControlThreadStatus {
    RUNNING,
    DETACHED,
    STOPPED,
} WASMDebugControlThreadStatus;

struct WASMDebugEngine;
struct WASMDebugInstance;

typedef struct WASMDebugControlThread {
    WASMGDBServer *server;
    korp_tid tid;
    korp_mutex wait_lock;
    char ip_addr[128];
    int port;
    WASMDebugControlThreadStatus status;
    struct WASMDebugEngine *debug_engine;
    struct WASMDebugInstance *debug_instance;
} WASMDebugControlThread;

typedef struct WASMDebugBreakPoint {
    struct WASMDebugBreakPoint *next;
    uint64 addr;
    uint64 orignal_data;
} WASMDebugBreakPoint;

typedef struct WASMDebugWatchPoint {
    bh_list_link next;
    uint64 addr;
    uint64 length;
} WASMDebugWatchPoint;

typedef enum debug_state_t {
    /* Debugger state conversion sequence:
     *   DBG_LAUNCHING ---> APP_STOPPED <---> APP_RUNNING
     */
    DBG_LAUNCHING,
    APP_RUNNING,
    APP_STOPPED,
    DBG_ERROR
} debug_state_t;

typedef struct WASMDebugExecutionMemory {
    uint32 start_offset;
    uint32 size;
    uint32 current_pos;
} WASMDebugExecutionMemory;

struct WASMDebugInstance {
    struct WASMDebugInstance *next;
    WASMDebugControlThread *control_thread;
    bh_list break_point_list;
    bh_list watch_point_list_read;
    bh_list watch_point_list_write;
    WASMCluster *cluster;
    uint32 id;
    korp_tid current_tid;
    korp_mutex wait_lock;
    korp_cond wait_cond;
    /* Last stopped thread, it should be set to NULL when sending
     * out the thread stop reply */
    WASMExecEnv *volatile stopped_thread;
    /* Currently status of the debug instance, it will be set to
     * RUNNING when receiving STEP/CONTINUE commands, and set to
     * STOPPED when any thread stopped */
    volatile debug_state_t current_state;
    /* Execution memory info. During debugging, the debug client may request to
     * malloc a memory space to evaluate user expressions. We preserve a buffer
     * during creating debug instance, and use a simple bump pointer allocator
     * to serve lldb's memory request */
    WASMDebugExecutionMemory exec_mem_info;
};

typedef enum WASMDebugEventKind {
    BREAK_POINT_ADD,
    BREAK_POINT_REMOVE
} WASMDebugEventKind;

typedef struct WASMDebugEvent {
    WASMDebugEventKind kind;
    unsigned char metadata[0];
} WASMDebugEvent;

typedef struct WASMDebugMemoryInfo {
    uint64 start;
    uint64 size;
    char name[128];
    char permisson[4];
} WASMDebugMemoryInfo;

typedef enum WasmAddressType {
    WasmMemory = 0x00,
    WasmObj = 0x01,
    WasmInvalid = 0x03
} WasmAddressType;

#define WASM_ADDR(type, id, offset) \
    (((uint64)type << 62) | ((uint64)0 << 32) | ((uint64)offset << 0))

#define WASM_ADDR_TYPE(addr) (((addr)&0xC000000000000000) >> 62)
#define WASM_ADDR_OFFSET(addr) (((addr)&0x00000000FFFFFFFF))

#define INVALIED_ADDR (0xFFFFFFFFFFFFFFFF)

void
on_thread_stop_event(WASMDebugInstance *debug_inst, WASMExecEnv *exec_env);

void
on_thread_exit_event(WASMDebugInstance *debug_inst, WASMExecEnv *exec_env);

WASMDebugInstance *
wasm_debug_instance_create(WASMCluster *cluster, int32 port);

void
wasm_debug_instance_destroy(WASMCluster *cluster);

WASMDebugInstance *
wasm_exec_env_get_instance(WASMExecEnv *exec_env);

bool
wasm_debug_engine_init(char *ip_addr, int32 process_port);

void
wasm_debug_engine_destroy();

WASMExecEnv *
wasm_debug_instance_get_current_env(WASMDebugInstance *instance);

uint64
wasm_debug_instance_get_pid(WASMDebugInstance *instance);

korp_tid
wasm_debug_instance_get_tid(WASMDebugInstance *instance);

uint32
wasm_debug_instance_get_tids(WASMDebugInstance *instance, korp_tid tids[],
                             uint32 len);

void
wasm_debug_instance_set_cur_thread(WASMDebugInstance *instance, korp_tid tid);

uint64
wasm_debug_instance_get_pc(WASMDebugInstance *instance);

uint64
wasm_debug_instance_get_load_addr(WASMDebugInstance *instance);

WASMDebugMemoryInfo *
wasm_debug_instance_get_memregion(WASMDebugInstance *instance, uint64 addr);

void
wasm_debug_instance_destroy_memregion(WASMDebugInstance *instance,
                                      WASMDebugMemoryInfo *mem_info);

bool
wasm_debug_instance_get_obj_mem(WASMDebugInstance *instance, uint64 addr,
                                char *buf, uint64 *size);

bool
wasm_debug_instance_get_linear_mem(WASMDebugInstance *instance, uint64 addr,
                                   char *buf, uint64 *size);

bool
wasm_debug_instance_get_mem(WASMDebugInstance *instance, uint64 addr, char *buf,
                            uint64 *size);

bool
wasm_debug_instance_set_mem(WASMDebugInstance *instance, uint64 addr, char *buf,
                            uint64 *size);

uint32
wasm_debug_instance_get_call_stack_pcs(WASMDebugInstance *instance,
                                       korp_tid tid, uint64 buf[], uint64 size);

bool
wasm_debug_instance_add_breakpoint(WASMDebugInstance *instance, uint64 addr,
                                   uint64 length);

bool
wasm_debug_instance_remove_breakpoint(WASMDebugInstance *instance, uint64 addr,
                                      uint64 length);

bool
wasm_debug_instance_watchpoint_write_add(WASMDebugInstance *instance,
                                         uint64 addr, uint64 length);

bool
wasm_debug_instance_watchpoint_write_remove(WASMDebugInstance *instance,
                                            uint64 addr, uint64 length);

bool
wasm_debug_instance_watchpoint_read_add(WASMDebugInstance *instance,
                                        uint64 addr, uint64 length);

bool
wasm_debug_instance_watchpoint_read_remove(WASMDebugInstance *instance,
                                           uint64 addr, uint64 length);

bool
wasm_debug_instance_on_failure(WASMDebugInstance *instance);

bool
wasm_debug_instance_interrupt_all_threads(WASMDebugInstance *instance);

bool
wasm_debug_instance_continue(WASMDebugInstance *instance);

bool
wasm_debug_instance_detach(WASMDebugInstance *instance);

bool
wasm_debug_instance_kill(WASMDebugInstance *instance);

uint32
wasm_debug_instance_get_thread_status(WASMDebugInstance *instance,
                                      korp_tid tid);

bool
wasm_debug_instance_singlestep(WASMDebugInstance *instance, korp_tid tid);

bool
wasm_debug_instance_get_local(WASMDebugInstance *instance, int32 frame_index,
                              int32 local_index, char buf[], int32 *size);

bool
wasm_debug_instance_get_global(WASMDebugInstance *instance, int32 frame_index,
                               int32 global_index, char buf[], int32 *size);

#if WASM_ENABLE_LIBC_WASI != 0
bool
wasm_debug_instance_get_current_object_name(WASMDebugInstance *instance,
                                            char name_buffer[], uint32 len);
#endif

uint64
wasm_debug_instance_mmap(WASMDebugInstance *instance, uint32 size,
                         int32 map_prot);

bool
wasm_debug_instance_ummap(WASMDebugInstance *instance, uint64 addr);
#endif
