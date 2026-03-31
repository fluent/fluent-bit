/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef HANDLER_H
#define HANDLER_H

#include "gdbserver.h"

int
wasm_debug_handler_init(void);

void
wasm_debug_handler_deinit(void);

void
handle_interrupt(WASMGDBServer *server);

void
handle_general_set(WASMGDBServer *server, char *payload);

void
handle_general_query(WASMGDBServer *server, char *payload);

void
handle_v_packet(WASMGDBServer *server, char *payload);

void
handle_threadstop_request(WASMGDBServer *server, char *payload);

void
handle_set_current_thread(WASMGDBServer *server, char *payload);

void
handle_get_register(WASMGDBServer *server, char *payload);

void
handle_get_json_request(WASMGDBServer *server, char *payload);

void
handle_get_read_binary_memory(WASMGDBServer *server, char *payload);

void
handle_get_read_memory(WASMGDBServer *server, char *payload);

void
handle_get_write_memory(WASMGDBServer *server, char *payload);

void
handle_add_break(WASMGDBServer *server, char *payload);

void
handle_remove_break(WASMGDBServer *server, char *payload);

void
handle_continue_request(WASMGDBServer *server, char *payload);

void
handle_kill_request(WASMGDBServer *server, char *payload);

void
handle____request(WASMGDBServer *server, char *payload);

void
handle_detach_request(WASMGDBServer *server, char *payload);

void
send_thread_stop_status(WASMGDBServer *server, uint32 status, korp_tid tid);
#endif
