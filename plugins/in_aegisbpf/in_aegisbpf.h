/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_IN_AEGISBPF_H
#define FLB_IN_AEGISBPF_H

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define FLB_IN_AEGISBPF_DEFAULT_SOCKET  "/var/run/aegisbpf/aegisbpf.sock"
#define FLB_IN_AEGISBPF_DEFAULT_RECONN  2      /* seconds */
#define FLB_IN_AEGISBPF_BUF_INIT        16384  /* initial line-assembly buffer */
#define FLB_IN_AEGISBPF_BUF_MAX         (1024 * 1024) /* cap: drop a pathological line */
#define FLB_IN_AEGISBPF_DRAIN_MAX       (4 * 1024 * 1024) /* max bytes drained per collector wake */

struct flb_in_aegisbpf {
    /* config */
    flb_sds_t socket_path;   /* AegisBPF control socket path */
    int reconnect_sec;       /* reconnect interval */

    /* connection state */
    int fd;                  /* stream socket fd, -1 when disconnected */
    int connected;
    int handshake_done;      /* the agent's first line is a streaming ack; skip it */
    int skipping_line;       /* discarding the tail of an over-length line */
    int coll_fd_reconnect;   /* time collector: (re)connect */
    int coll_fd_read;        /* socket collector: drain events */

    /* line assembly */
    char *buf;
    size_t buf_size;
    size_t buf_len;

    struct flb_log_event_encoder *encoder;
    struct flb_input_instance *ins;
};

#endif
