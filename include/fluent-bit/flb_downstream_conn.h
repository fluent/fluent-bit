/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_DOWNSTREAM_CONN_H
#define FLB_DOWNSTREAM_CONN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_config.h>

#ifdef FLB_HAVE_TLS
#endif

struct flb_downstream;

/* Downstream TCP connection */
struct flb_downstream_conn {
    struct mk_event event;
    struct flb_coro *coro;
    struct flb_downstream *stream;
    void *linked_object; /* temporary */\

    /* Socket */
    flb_sockfd_t fd;
    int port;
    char *host;


    /*
     * Custom 'error' for the connection file descriptor. Commonly used to
     * specify a reason for an exception that was generated locally: consider
     * a connect timeout, we shutdown(2) the connection but in reallity we
     * might want to express an 'ETIMEDOUT'
     */
    int net_error;

    /* If this flag is set, then destroy_conn will ignore this connection, this
     * helps mitigate issues caused by flb_upstream_conn_timeouts marking a connection
     * to be dropped and the event loop manager function destroying that connection
     * at the end of the cycle while the connection coroutine is still suspended which
     * causes the outer functions to access invalid memory when handling the error amongst
     * other things.
     */
    int busy_flag;

    /* Connect */
    time_t ts_connect_start;
    time_t ts_connect_timeout;

    /* Event loop */
    struct mk_event_loop *evl;

    /*
     * Link to list head on flb_upstream, if the connection is busy,
     * it's linked to 'busy_queue', otherwise it resides in 'av_queue'
     * so it can be used by a plugin.
     */
    struct mk_list _head;

#ifdef FLB_HAVE_TLS
    /* TLS context (general context for the Upstream) */
    struct flb_tls *tls;

    /* Each TCP connections using TLS needs a session */
    struct flb_tls_session *tls_session;
#endif
};

int flb_downstream_conn_release(struct flb_downstream_conn *connection);
int flb_downstream_conn_timeouts(struct mk_list *list);
int flb_downstream_conn_pending_destroy(struct flb_downstream *downstream);

#endif
