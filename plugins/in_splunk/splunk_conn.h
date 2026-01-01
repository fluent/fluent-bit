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

#ifndef FLB_IN_SPLUNK_CONN
#define FLB_IN_SPLUNK_CONN

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_connection.h>

#include <monkey/mk_http.h>
#include <monkey/mk_http_parser.h>
#include <monkey/mk_utils.h>

struct splunk_conn {
    /* Buffer */
    char *buf_data;             /* Buffer data                       */
    int  buf_len;               /* Data length                       */
    int  buf_size;              /* Buffer size                       */

    /*
     * Parser context: we only held one parser per connection
     * which is re-used everytime we have a new request.
     */
    struct mk_http_parser parser;
    struct mk_http_request request;
    struct mk_http_session session;
    struct flb_connection *connection;

    void *ctx;                  /* Plugin parent context             */
    struct mk_list _head;       /* link to flb_http->connections     */
};

struct splunk_conn *splunk_conn_add(struct flb_connection *connection, struct flb_splunk *ctx);
int splunk_conn_del(struct splunk_conn *conn);
void splunk_conn_release_all(struct flb_splunk *ctx);


#endif
