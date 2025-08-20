/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _GDB_SERVER_H
#define _GDB_SERVER_H

#include "bh_platform.h"

#define PACKET_BUF_SIZE 0x8000

enum GDBStoppointType {
    eStoppointInvalid = -1,
    eBreakpointSoftware = 0,
    eBreakpointHardware,
    eWatchpointWrite,
    eWatchpointRead,
    eWatchpointReadWrite
};

typedef enum rsp_recv_phase_t {
    Phase_Idle,
    Phase_Payload,
    Phase_Checksum
} rsp_recv_phase_t;

/* Remote Serial Protocol Receive Context */
typedef struct rsp_recv_context_t {
    rsp_recv_phase_t phase;
    uint16 receive_index;
    uint16 size_in_phase;
    uint8 check_sum;
    /* RSP packet should not be too long */
    char receive_buffer[1024];
} rsp_recv_context_t;

typedef struct WasmDebugPacket {
    unsigned char buf[PACKET_BUF_SIZE];
    uint32 size;
} WasmDebugPacket;

struct WASMDebugControlThread;
typedef struct WASMGDBServer {
    bh_socket_t listen_fd;
    bh_socket_t socket_fd;
    WasmDebugPacket pkt;
    bool noack;
    struct WASMDebugControlThread *thread;
    rsp_recv_context_t *receive_ctx;
} WASMGDBServer;

WASMGDBServer *
wasm_create_gdbserver(const char *host, int32 *port);

bool
wasm_gdbserver_listen(WASMGDBServer *server);

bool
wasm_gdbserver_accept(WASMGDBServer *server);

void
wasm_gdbserver_detach(WASMGDBServer *server);

void
wasm_close_gdbserver(WASMGDBServer *server);

bool
wasm_gdbserver_handle_packet(WASMGDBServer *server);
#endif
