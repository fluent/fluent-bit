/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_IN_SYSLOG_H
#define FLB_IN_SYSLOG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>

/* Syslog modes */
#define FLB_SYSLOG_UNIX_TCP  1
#define FLB_SYSLOG_UNIX_UDP  2
#define FLB_SYSLOG_TCP       3
#define FLB_SYSLOG_UDP       4

/* 32KB chunk size */
#define FLB_SYSLOG_CHUNK   "32768"

/* TCP framing */
#define FLB_SYSLOG_FRAME_NEWLINE        0
#define FLB_SYSLOG_FRAME_OCTET_COUNTING 1

struct syslog_conn;

/* Context / Config*/
struct flb_syslog {
    /* Listening mode: unix udp, unix tcp or normal tcp */
    flb_sds_t mode_str;
    int mode;

    /* Network mode */
    char *listen;
    char *port;

    /* Unix socket (UDP/TCP)*/
    int server_fd;
    flb_sds_t unix_path;
    flb_sds_t unix_perm_str;
    unsigned int unix_perm;
    size_t receive_buffer_size;

    /* UDP buffer, data length and buffer size */
        // char *buffer_data;
        // size_t buffer_len;
        // size_t buffer_size;

    /* Buffers setup */
    size_t buffer_max_size;
    size_t buffer_chunk_size;

    /* Configuration */
    flb_sds_t parser_name;
    struct flb_parser *parser;
    flb_sds_t raw_message_key;
    flb_sds_t source_address_key;

    /* TCP framing */
    flb_sds_t format_str;
    int frame_type;

    int dgram_mode_flag;
    int collector_id;
    struct mk_event *collector_event;
    struct flb_downstream *downstream;
    struct syslog_conn *dummy_conn;

    /* List for connections and event loop */
    struct mk_list connections;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

#endif
