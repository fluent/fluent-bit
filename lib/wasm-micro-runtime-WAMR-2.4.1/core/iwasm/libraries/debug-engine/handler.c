/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "handler.h"
#include "debug_engine.h"
#include "packets.h"
#include "utils.h"
#include "wasm_runtime.h"

/*
 * Note: A moderate MAX_PACKET_SIZE is ok because
 * LLDB queries our buffer size (via qSupported PacketSize)
 * and limits packet sizes accordingly.
 */

#if defined(DEBUG_MAX_PACKET_SIZE)
#define MAX_PACKET_SIZE DEBUG_MAX_PACKET_SIZE
#else
#define MAX_PACKET_SIZE (4096)
#endif

/*
 * Note: It's assumed that MAX_PACKET_SIZE is reasonably large.
 * See GetWorkingDir, WasmCallStack, etc.
 */
#if MAX_PACKET_SIZE < PATH_MAX || MAX_PACKET_SIZE < (2048 + 1)
#error MAX_PACKET_SIZE is too small
#endif

static char *tmpbuf;
static korp_mutex tmpbuf_lock;

int
wasm_debug_handler_init(void)
{
    int ret;
    tmpbuf = wasm_runtime_malloc(MAX_PACKET_SIZE);
    if (tmpbuf == NULL) {
        LOG_ERROR("debug-engine: Packet buffer allocation failure");
        return BHT_ERROR;
    }
    ret = os_mutex_init(&tmpbuf_lock);
    if (ret != BHT_OK) {
        wasm_runtime_free(tmpbuf);
        tmpbuf = NULL;
    }
    return ret;
}

void
wasm_debug_handler_deinit(void)
{
    wasm_runtime_free(tmpbuf);
    tmpbuf = NULL;
    os_mutex_destroy(&tmpbuf_lock);
}

void
handle_interrupt(WASMGDBServer *server)
{
    wasm_debug_instance_interrupt_all_threads(server->thread->debug_instance);
}

void
handle_general_set(WASMGDBServer *server, char *payload)
{
    const char *name;
    char *args;

    args = strchr(payload, ':');
    if (args)
        *args++ = '\0';

    name = payload;
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);

    if (!strcmp(name, "StartNoAckMode")) {
        server->noack = true;
        write_packet(server, "OK");
    }
    if (!strcmp(name, "ThreadSuffixSupported")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "ListThreadsInStopReply")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "EnableErrorStrings")) {
        write_packet(server, "OK");
    }
}

static void
process_xfer(WASMGDBServer *server, const char *name, char *args)
{
    const char *mode = args;

    args = strchr(args, ':');
    if (args)
        *args++ = '\0';

    if (!strcmp(name, "libraries") && !strcmp(mode, "read")) {
        // TODO: how to get current wasm file name?
        uint64 addr = wasm_debug_instance_get_load_addr(
            (WASMDebugInstance *)server->thread->debug_instance);
        os_mutex_lock(&tmpbuf_lock);
#if WASM_ENABLE_LIBC_WASI != 0
        char objname[128];
        if (!wasm_debug_instance_get_current_object_name(
                (WASMDebugInstance *)server->thread->debug_instance, objname,
                128)) {
            objname[0] = 0; /* use an empty string */
        }
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "l<library-list><library name=\"%s\"><section "
                 "address=\"0x%" PRIx64 "\"/></library></library-list>",
                 objname, addr);
#else
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "l<library-list><library name=\"%s\"><section "
                 "address=\"0x%" PRIx64 "\"/></library></library-list>",
                 "nobody.wasm", addr);
#endif
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
}

void
process_wasm_local(WASMGDBServer *server, char *args)
{
    int32 frame_index;
    int32 local_index;
    char buf[16];
    int32 size = 16;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "E01");
    if (sscanf(args, "%" PRId32 ";%" PRId32, &frame_index, &local_index) == 2) {
        ret = wasm_debug_instance_get_local(
            (WASMDebugInstance *)server->thread->debug_instance, frame_index,
            local_index, buf, &size);
        if (ret && size > 0) {
            mem2hex(buf, tmpbuf, size);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
process_wasm_global(WASMGDBServer *server, char *args)
{
    int32 frame_index;
    int32 global_index;
    char buf[16];
    int32 size = 16;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "E01");
    if (sscanf(args, "%" PRId32 ";%" PRId32, &frame_index, &global_index)
        == 2) {
        ret = wasm_debug_instance_get_global(
            (WASMDebugInstance *)server->thread->debug_instance, frame_index,
            global_index, buf, &size);
        if (ret && size > 0) {
            mem2hex(buf, tmpbuf, size);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

/* TODO: let server send an empty/error reply.
   Original issue: 4265
   Not tested yet, but it should work.
 */
static void
send_reply(WASMGDBServer *server, const char *err)
{
    if (!err || !*err)
        write_packet(server, "");
    else
        write_packet(server, err);
}

void
handle_general_query(WASMGDBServer *server, char *payload)
{
    const char *name;
    char *args;
    char triple[256];

    args = strchr(payload, ':');
    if (args)
        *args++ = '\0';
    name = payload;
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);

    if (!strcmp(name, "C")) {
        uint64 pid, tid;
        pid = wasm_debug_instance_get_pid(
            (WASMDebugInstance *)server->thread->debug_instance);
        tid = (uint64)(uintptr_t)wasm_debug_instance_get_tid(
            (WASMDebugInstance *)server->thread->debug_instance);

        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE, "QCp%" PRIx64 ".%" PRIx64 "", pid,
                 tid);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    if (!strcmp(name, "Supported")) {
        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "qXfer:libraries:read+;PacketSize=%x;", MAX_PACKET_SIZE);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }

    if (!strcmp(name, "Xfer")) {
        name = args;

        if (!args) {
            LOG_ERROR("payload parse error during handle_general_query");
            send_reply(server, "");
            return;
        }

        args = strchr(args, ':');

        if (args) {
            *args++ = '\0';
            process_xfer(server, name, args);
        }
    }

    if (!strcmp(name, "HostInfo")) {
        mem2hex("wasm32-wamr-wasi-wasm", triple,
                strlen("wasm32-wamr-wasi-wasm"));

        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "vendor:wamr;ostype:wasi;arch:wasm32;"
                 "triple:%s;endian:little;ptrsize:4;",
                 triple);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    if (!strcmp(name, "ModuleInfo")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "GetWorkingDir")) {
        os_mutex_lock(&tmpbuf_lock);
        if (getcwd(tmpbuf, PATH_MAX))
            write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    if (!strcmp(name, "QueryGDBServer")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "VAttachOrWaitSupported")) {
        write_packet(server, "");
    }
    if (!strcmp(name, "ProcessInfo")) {
        // Todo: process id parent-pid
        uint64 pid;
        pid = wasm_debug_instance_get_pid(
            (WASMDebugInstance *)server->thread->debug_instance);
        mem2hex("wasm32-wamr-wasi-wasm", triple,
                strlen("wasm32-wamr-wasi-wasm"));

        os_mutex_lock(&tmpbuf_lock);
        snprintf(tmpbuf, MAX_PACKET_SIZE,
                 "pid:%" PRIx64 ";parent-pid:%" PRIx64
                 ";vendor:wamr;ostype:wasi;arch:wasm32;"
                 "triple:%s;endian:little;ptrsize:4;",
                 pid, pid, triple);
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    if (!strcmp(name, "RegisterInfo0")) {
        os_mutex_lock(&tmpbuf_lock);
        snprintf(
            tmpbuf, MAX_PACKET_SIZE,
            "name:pc;alt-name:pc;bitsize:64;offset:0;encoding:uint;format:hex;"
            "set:General Purpose Registers;gcc:16;dwarf:16;generic:pc;");
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
    else if (!strncmp(name, "RegisterInfo", strlen("RegisterInfo"))) {
        write_packet(server, "E45");
    }
    if (!strcmp(name, "StructuredDataPlugins")) {
        write_packet(server, "");
    }

    if (args && (!strcmp(name, "MemoryRegionInfo"))) {
        uint64 addr = strtoll(args, NULL, 16);
        WASMDebugMemoryInfo *mem_info = wasm_debug_instance_get_memregion(
            (WASMDebugInstance *)server->thread->debug_instance, addr);
        if (mem_info) {
            char name_buf[256];
            mem2hex(mem_info->name, name_buf, strlen(mem_info->name));

            os_mutex_lock(&tmpbuf_lock);
            snprintf(tmpbuf, MAX_PACKET_SIZE,
                     "start:%" PRIx64 ";size:%" PRIx64
                     ";permissions:%s;name:%s;",
                     (uint64)mem_info->start, mem_info->size,
                     mem_info->permisson, name_buf);
            write_packet(server, tmpbuf);
            os_mutex_unlock(&tmpbuf_lock);

            wasm_debug_instance_destroy_memregion(
                (WASMDebugInstance *)server->thread->debug_instance, mem_info);
        }
    }

    if (!strcmp(name, "WasmData")) {
        write_packet(server, "");
    }

    if (!strcmp(name, "WasmMem")) {
        write_packet(server, "");
    }

    if (!strcmp(name, "Symbol")) {
        write_packet(server, "");
    }

    if (args && (!strcmp(name, "WasmCallStack"))) {
        uint64 tid = strtoll(args, NULL, 16);
        uint64 buf[1024 / sizeof(uint64)];
        uint32 count = wasm_debug_instance_get_call_stack_pcs(
            (WASMDebugInstance *)server->thread->debug_instance,
            (korp_tid)(uintptr_t)tid, buf, 1024 / sizeof(uint64));

        if (count > 0) {
            os_mutex_lock(&tmpbuf_lock);
            mem2hex((char *)buf, tmpbuf, count * sizeof(uint64));
            write_packet(server, tmpbuf);
            os_mutex_unlock(&tmpbuf_lock);
        }
        else
            write_packet(server, "");
    }

    if (args && (!strcmp(name, "WasmLocal"))) {
        process_wasm_local(server, args);
    }

    if (args && (!strcmp(name, "WasmGlobal"))) {
        process_wasm_global(server, args);
    }

    if (!strcmp(name, "Offsets")) {
        write_packet(server, "");
    }

    if (!strncmp(name, "ThreadStopInfo", strlen("ThreadStopInfo"))) {
        int32 prefix_len = strlen("ThreadStopInfo");
        uint64 tid_number = strtoll(name + prefix_len, NULL, 16);
        korp_tid tid = (korp_tid)(uintptr_t)tid_number;
        uint32 status;

        status = wasm_debug_instance_get_thread_status(
            server->thread->debug_instance, tid);

        send_thread_stop_status(server, status, tid);
    }

    if (!strcmp(name, "WatchpointSupportInfo")) {
        os_mutex_lock(&tmpbuf_lock);
        // Any uint32 is OK for the watchpoint support
        snprintf(tmpbuf, MAX_PACKET_SIZE, "num:32;");
        write_packet(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
    }
}

void
send_thread_stop_status(WASMGDBServer *server, uint32 status, korp_tid tid)
{
    int32 len = 0;
    uint64 pc;
    korp_tid tids[20];
    char pc_string[17];
    uint32 tids_count, i = 0;
    uint32 gdb_status = status;
    WASMExecEnv *exec_env;
    const char *exception;

    if (status == 0) {
        os_mutex_lock(&tmpbuf_lock);
        (void)snprintf(tmpbuf, MAX_PACKET_SIZE, "W%02" PRIx32, status);
        send_reply(server, tmpbuf);
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }
    tids_count = wasm_debug_instance_get_tids(
        (WASMDebugInstance *)server->thread->debug_instance, tids, 20);
    pc = wasm_debug_instance_get_pc(
        (WASMDebugInstance *)server->thread->debug_instance);

    if (status == WAMR_SIG_SINGSTEP) {
        gdb_status = WAMR_SIG_TRAP;
    }

    os_mutex_lock(&tmpbuf_lock);
    // TODO: how name a wasm thread?
    len = snprintf(tmpbuf, MAX_PACKET_SIZE,
                   "T%02" PRIx32 "thread:%" PRIx64 ";name:%s;", gdb_status,
                   (uint64)(uintptr_t)tid, "nobody");
    if (len < 0 || len >= MAX_PACKET_SIZE) {
        send_reply(server, "E01");
        os_mutex_unlock(&tmpbuf_lock);
        return;
    }

    if (tids_count > 0) {
        int n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len, "threads:");
        if (n < 0 || n >= MAX_PACKET_SIZE - len) {
            send_reply(server, "E01");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }

        len += n;
        while (i < tids_count) {
            if (i == tids_count - 1) {
                n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                             "%" PRIx64 ";", (uint64)(uintptr_t)tids[i]);
            }
            else {
                n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                             "%" PRIx64 ",", (uint64)(uintptr_t)tids[i]);
            }

            if (n < 0 || n >= MAX_PACKET_SIZE - len) {
                send_reply(server, "E01");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }

            len += n;
            i++;
        }
    }
    mem2hex((void *)&pc, pc_string, 8);
    pc_string[8 * 2] = '\0';

    exec_env = wasm_debug_instance_get_current_env(
        (WASMDebugInstance *)server->thread->debug_instance);
    bh_assert(exec_env);

    exception =
        wasm_runtime_get_exception(wasm_runtime_get_module_inst(exec_env));
    if (exception) {
        /* When exception occurs, use reason:exception so the description can be
         * correctly processed by LLDB */
        uint32 exception_len = strlen(exception);
        int n =
            snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                     "thread-pcs:%" PRIx64 ";00:%s;reason:%s;description:", pc,
                     pc_string, "exception");
        if (n < 0 || n >= MAX_PACKET_SIZE - len) {
            send_reply(server, "E01");
            os_mutex_unlock(&tmpbuf_lock);
            return;
        }

        len += n;
        /* The description should be encoded as HEX */
        for (i = 0; i < exception_len; i++) {
            n = snprintf(tmpbuf + len, MAX_PACKET_SIZE - len, "%02x",
                         exception[i]);
            if (n < 0 || n >= MAX_PACKET_SIZE - len) {
                send_reply(server, "E01");
                os_mutex_unlock(&tmpbuf_lock);
                return;
            }

            len += n;
        }

        (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len, ";");
    }
    else {
        if (status == WAMR_SIG_TRAP) {
            (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                           "thread-pcs:%" PRIx64 ";00:%s;reason:%s;", pc,
                           pc_string, "breakpoint");
        }
        else if (status == WAMR_SIG_SINGSTEP) {
            (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                           "thread-pcs:%" PRIx64 ";00:%s;reason:%s;", pc,
                           pc_string, "trace");
        }
        else { /* status > 0 (== 0 is checked at the function beginning) */
            (void)snprintf(tmpbuf + len, MAX_PACKET_SIZE - len,
                           "thread-pcs:%" PRIx64 ";00:%s;reason:%s;", pc,
                           pc_string, "signal");
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_v_packet(WASMGDBServer *server, char *payload)
{
    const char *name;
    char *args;

    args = strchr(payload, ';');
    if (args)
        *args++ = '\0';
    name = payload;
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);

    if (!strcmp("Cont?", name))
        write_packet(server, "vCont;c;C;s;S;");

    if (!strcmp("Cont", name)) {
        if (args) {
            if (args[0] == 's' || args[0] == 'c') {
                char *numstring = strchr(args, ':');
                if (numstring) {
                    uint64 tid_number;
                    korp_tid tid;

                    *numstring++ = '\0';
                    tid_number = strtoll(numstring, NULL, 16);
                    tid = (korp_tid)(uintptr_t)tid_number;
                    wasm_debug_instance_set_cur_thread(
                        (WASMDebugInstance *)server->thread->debug_instance,
                        tid);

                    if (args[0] == 's') {
                        wasm_debug_instance_singlestep(
                            (WASMDebugInstance *)server->thread->debug_instance,
                            tid);
                    }
                    else {
                        wasm_debug_instance_continue(
                            (WASMDebugInstance *)
                                server->thread->debug_instance);
                    }
                }
            }
        }
    }
}

void
handle_threadstop_request(WASMGDBServer *server, char *payload)
{
    korp_tid tid;
    uint32 status;
    WASMDebugInstance *debug_inst =
        (WASMDebugInstance *)server->thread->debug_instance;
    bh_assert(debug_inst);

    /* According to
       https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#Packets, the "?"
       package should be sent when connection is first established to query the
       reason the target halted */
    bh_assert(debug_inst->current_state == DBG_LAUNCHING);

    /* Waiting for the stop event */
    os_mutex_lock(&debug_inst->wait_lock);
    while (!debug_inst->stopped_thread) {
        os_cond_wait(&debug_inst->wait_cond, &debug_inst->wait_lock);
    }
    os_mutex_unlock(&debug_inst->wait_lock);

    tid = debug_inst->stopped_thread->handle;
    status = (uint32)debug_inst->stopped_thread->current_status->signal_flag;

    wasm_debug_instance_set_cur_thread(debug_inst, tid);

    send_thread_stop_status(server, status, tid);

    debug_inst->current_state = APP_STOPPED;
    debug_inst->stopped_thread = NULL;
}

void
handle_set_current_thread(WASMGDBServer *server, char *payload)
{
    LOG_VERBOSE("%s:%s\n", __FUNCTION__, payload);
    if ('g' == *payload++) {
        uint64 tid = strtoll(payload, NULL, 16);
        if (tid > 0)
            wasm_debug_instance_set_cur_thread(
                (WASMDebugInstance *)server->thread->debug_instance,
                (korp_tid)(uintptr_t)tid);
    }
    write_packet(server, "OK");
}

void
handle_get_register(WASMGDBServer *server, char *payload)
{
    uint64 regdata;
    int32 i = strtol(payload, NULL, 16);

    if (i != 0) {
        send_reply(server, "E01");
        return;
    }
    regdata = wasm_debug_instance_get_pc(
        (WASMDebugInstance *)server->thread->debug_instance);

    os_mutex_lock(&tmpbuf_lock);
    mem2hex((void *)&regdata, tmpbuf, 8);
    tmpbuf[8 * 2] = '\0';
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_get_json_request(WASMGDBServer *server, char *payload)
{
    char *args;

    args = strchr(payload, ':');
    if (args)
        *args++ = '\0';
    write_packet(server, "");
}

void
handle_get_read_binary_memory(WASMGDBServer *server, char *payload)
{
    write_packet(server, "");
}

void
handle_get_read_memory(WASMGDBServer *server, char *payload)
{
    uint64 maddr, mlen;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "");
    if (sscanf(payload, "%" SCNx64 ",%" SCNx64, &maddr, &mlen) == 2) {
        char *buff;

        if (mlen * 2 > MAX_PACKET_SIZE) {
            LOG_ERROR("Buffer overflow!");
            mlen = MAX_PACKET_SIZE / 2;
        }

        buff = wasm_runtime_malloc(mlen);
        if (buff) {
            ret = wasm_debug_instance_get_mem(
                (WASMDebugInstance *)server->thread->debug_instance, maddr,
                buff, &mlen);
            if (ret) {
                mem2hex(buff, tmpbuf, mlen);
            }
            wasm_runtime_free(buff);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_get_write_memory(WASMGDBServer *server, char *payload)
{
    size_t hex_len;
    int offset;
    int32 act_len;
    uint64 maddr, mlen;
    char *buff;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "");
    if (sscanf(payload, "%" SCNx64 ",%" SCNx64 ":%n", &maddr, &mlen, &offset)
        == 2) {
        payload += offset;
        hex_len = strlen(payload);
        act_len = hex_len / 2 < mlen ? hex_len / 2 : mlen;

        buff = wasm_runtime_malloc(act_len);
        if (buff) {
            hex2mem(payload, buff, act_len);
            ret = wasm_debug_instance_set_mem(
                (WASMDebugInstance *)server->thread->debug_instance, maddr,
                buff, &mlen);
            if (ret) {
                snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "OK");
            }
            wasm_runtime_free(buff);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle_breakpoint_software_add(WASMGDBServer *server, uint64 addr,
                               size_t length)
{
    bool ret = wasm_debug_instance_add_breakpoint(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_breakpoint_software_remove(WASMGDBServer *server, uint64 addr,
                                  size_t length)
{
    bool ret = wasm_debug_instance_remove_breakpoint(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_write_add(WASMGDBServer *server, uint64 addr, size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_write_add(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_write_remove(WASMGDBServer *server, uint64 addr,
                               size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_write_remove(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_read_add(WASMGDBServer *server, uint64 addr, size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_read_add(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_watchpoint_read_remove(WASMGDBServer *server, uint64 addr, size_t length)
{
    bool ret = wasm_debug_instance_watchpoint_read_remove(
        (WASMDebugInstance *)server->thread->debug_instance, addr, length);
    write_packet(server, ret ? "OK" : "EO1");
}

void
handle_add_break(WASMGDBServer *server, char *payload)
{
    int arg_c;
    size_t type, length;
    uint64 addr;

    if ((arg_c = sscanf(payload, "%zx,%" SCNx64 ",%zx", &type, &addr, &length))
        != 3) {
        LOG_ERROR("Unsupported number of add break arguments %d", arg_c);
        send_reply(server, "");
        return;
    }

    switch (type) {
        case eBreakpointSoftware:
            handle_breakpoint_software_add(server, addr, length);
            break;
        case eWatchpointWrite:
            handle_watchpoint_write_add(server, addr, length);
            break;
        case eWatchpointRead:
            handle_watchpoint_read_add(server, addr, length);
            break;
        case eWatchpointReadWrite:
            handle_watchpoint_write_add(server, addr, length);
            handle_watchpoint_read_add(server, addr, length);
            break;
        default:
            LOG_ERROR("Unsupported breakpoint type %zu", type);
            write_packet(server, "");
            break;
    }
}

void
handle_remove_break(WASMGDBServer *server, char *payload)
{
    int arg_c;
    size_t type, length;
    uint64 addr;

    if ((arg_c = sscanf(payload, "%zx,%" SCNx64 ",%zx", &type, &addr, &length))
        != 3) {
        LOG_ERROR("Unsupported number of remove break arguments %d", arg_c);
        send_reply(server, "");
        return;
    }

    switch (type) {
        case eBreakpointSoftware:
            handle_breakpoint_software_remove(server, addr, length);
            break;
        case eWatchpointWrite:
            handle_watchpoint_write_remove(server, addr, length);
            break;
        case eWatchpointRead:
            handle_watchpoint_read_remove(server, addr, length);
            break;
        case eWatchpointReadWrite:
            handle_watchpoint_write_remove(server, addr, length);
            handle_watchpoint_read_remove(server, addr, length);
            break;
        default:
            LOG_ERROR("Unsupported breakpoint type %zu", type);
            write_packet(server, "");
            break;
    }
}

void
handle_continue_request(WASMGDBServer *server, char *payload)
{
    wasm_debug_instance_continue(
        (WASMDebugInstance *)server->thread->debug_instance);
}

void
handle_kill_request(WASMGDBServer *server, char *payload)
{
    wasm_debug_instance_kill(
        (WASMDebugInstance *)server->thread->debug_instance);
}

static void
handle_malloc(WASMGDBServer *server, char *payload)
{
    char *args;
    uint64 addr, size;
    int32 map_prot = MMAP_PROT_NONE;

    args = strstr(payload, ",");
    if (args) {
        *args++ = '\0';
    }
    else {
        LOG_ERROR("Payload parse error during handle malloc");
        send_reply(server, "");
        return;
    }

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "E03");

    size = strtoll(payload, NULL, 16);
    if (size > 0) {
        while (*args) {
            if (*args == 'r') {
                map_prot |= MMAP_PROT_READ;
            }
            if (*args == 'w') {
                map_prot |= MMAP_PROT_WRITE;
            }
            if (*args == 'x') {
                map_prot |= MMAP_PROT_EXEC;
            }
            args++;
        }
        addr = wasm_debug_instance_mmap(
            (WASMDebugInstance *)server->thread->debug_instance, size,
            map_prot);
        if (addr) {
            snprintf(tmpbuf, MAX_PACKET_SIZE, "%" PRIx64, addr);
        }
    }
    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

static void
handle_free(WASMGDBServer *server, char *payload)
{
    uint64 addr;
    bool ret;

    os_mutex_lock(&tmpbuf_lock);
    snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "E03");
    addr = strtoll(payload, NULL, 16);

    ret = wasm_debug_instance_ummap(
        (WASMDebugInstance *)server->thread->debug_instance, addr);
    if (ret) {
        snprintf(tmpbuf, MAX_PACKET_SIZE, "%s", "OK");
    }

    write_packet(server, tmpbuf);
    os_mutex_unlock(&tmpbuf_lock);
}

void
handle____request(WASMGDBServer *server, char *payload)
{
    char *args;

    if (payload[0] == 'M') {
        args = payload + 1;
        handle_malloc(server, args);
    }
    if (payload[0] == 'm') {
        args = payload + 1;
        handle_free(server, args);
    }
}

void
handle_detach_request(WASMGDBServer *server, char *payload)
{
    if (payload != NULL) {
        write_packet(server, "OK");
    }
    wasm_debug_instance_detach(
        (WASMDebugInstance *)server->thread->debug_instance);
}
