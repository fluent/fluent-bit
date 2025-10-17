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

#ifndef FLB_IN_SYSLOG_CONN_H
#define FLB_IN_SYSLOG_CONN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_connection.h>

#include "syslog.h"

/* Respresents a connection */
struct syslog_conn {
    int status;                      /* Connection status                 */

    /* Buffer */
    char *buf_data;                  /* Buffer data                       */
    size_t buf_size;                 /* Buffer size                       */
    size_t buf_len;                  /* Buffer length                     */
    size_t buf_parsed;               /* Parsed buffer (offset)            */
    /* Octet-counting framing state */
    size_t frame_expected_len;       /* remaining message bytes needed    */
    int    frame_have_len;           /* 0 = need length, 1 = have length  */
    struct flb_input_instance *ins;  /* Parent plugin instance            */
    struct flb_syslog *ctx;          /* Plugin configuration context      */
    struct flb_connection *connection;

    struct mk_list _head;
};

int syslog_conn_event(void *data);
int syslog_stream_conn_event(void *data);
int syslog_dgram_conn_event(void *data);
struct syslog_conn *syslog_conn_add(struct flb_connection *connection,
                                    struct flb_syslog *ctx);
int syslog_conn_del(struct syslog_conn *conn);
int syslog_conn_exit(struct flb_syslog *ctx);

#endif
