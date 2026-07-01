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

#ifndef FLB_IN_UDP_CONN_H
#define FLB_IN_UDP_CONN_H

#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_connection.h>

#define FLB_IN_UDP_CHUNK "32768"

#define FLB_MAP_EXPAND_SUCCESS   0
#define FLB_MAP_NOT_MODIFIED    -1
#define FLB_MAP_EXPANSION_ERROR -2
#define FLB_MAP_EXPANSION_INVALID_VALUE_TYPE -3

struct udp_conn_stream {
    char *tag;
    size_t tag_len;
};

/* Respresents a connection */
struct udp_conn {
    /* Buffer */
    char *buf_data;                   /* Buffer data                       */
    int  buf_len;                     /* Data length                       */
    int  buf_size;                    /* Buffer size                       */

    struct flb_input_instance *ins;   /* Parent plugin instance            */
    struct flb_in_udp_config *ctx;    /* Plugin configuration context      */
    struct flb_pack_state pack_state; /* Internal JSON parser              */
    struct flb_connection *connection;

    struct mk_list _head;
};

struct udp_conn *udp_conn_add(struct flb_connection *connection, struct flb_in_udp_config *ctx);
int udp_conn_del(struct udp_conn *conn);
int udp_conn_event(void *data);

#endif
