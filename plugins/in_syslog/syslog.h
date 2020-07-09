/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

/* Syslog modes */
#define FLB_SYSLOG_UNIX_TCP  1
#define FLB_SYSLOG_UNIX_UDP  2
#define FLB_SYSLOG_TCP       3
#define FLB_SYSLOG_UDP       4

/* 32KB chunk size */
#define FLB_SYSLOG_CHUNK   32768

/* Context / Config*/
struct flb_syslog {
    /* Listening mode: unix udp, unix tcp or normal tcp */
    int mode;

    /* Network mode */
    char *listen;
    char *port;

    /* Unix socket (UDP/TCP)*/
    int server_fd;
    char *unix_path;
    unsigned int unix_perm;

    /* UDP buffer, data length and buffer size */
    char *buffer_data;
    size_t buffer_len;
    size_t buffer_size;

    /* Buffers setup */
    size_t buffer_max_size;
    size_t buffer_chunk_size;

    /* Configuration */
    struct flb_parser *parser;
    int dynamic_tag;

    /* List for connections and event loop */
    struct mk_list connections;
    struct mk_event_loop *evl;
    struct flb_input_instance *ins;
};

#endif
