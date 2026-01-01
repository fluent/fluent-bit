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

#ifndef FLB_IN_UNIX_SOCKET_CONN_H
#define FLB_IN_UNIX_SOCKET_CONN_H

#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_connection.h>

#define FLB_IN_UNIX_SOCKET_CHUNK "32768"

enum {
    UNIX_SOCKET_NEW        = 1,  /* it's a new connection                */
    UNIX_SOCKET_CONNECTED  = 2,  /* MQTT connection per protocol spec OK */
};

struct unix_socket_conn_stream {
    char *tag;
    size_t tag_len;
};

/* Respresents a connection */
struct unix_socket_conn {
    int status;                       /* Connection status                 */

    /* Buffer */
    char *buf_data;                   /* Buffer data                       */
    int  buf_len;                     /* Data length                       */
    int  buf_size;                    /* Buffer size                       */
    size_t rest;                      /* Unpacking offset                  */

    struct flb_input_instance *ins;   /* Parent plugin instance            */
    struct flb_in_unix_socket_config *ctx;    /* Plugin configuration context      */
    struct flb_pack_state pack_state; /* Internal JSON parser              */
    struct flb_connection *connection;

    struct mk_list _head;
};

struct unix_socket_conn *unix_socket_conn_add(struct flb_connection *connection, struct flb_in_unix_socket_config *ctx);
int unix_socket_conn_del(struct unix_socket_conn *conn);
int unix_socket_conn_event(void *data);

#endif
