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

#ifndef FLB_UPSTREAM_CONN_H
#define FLB_UPSTREAM_CONN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_config.h>

#ifdef FLB_HAVE_TLS
#include <mbedtls/net.h>
#endif

/* Upstream TCP connection */
struct flb_upstream_conn {
    struct mk_event event;
    struct flb_coro *coro;

    /* Socker */
    flb_sockfd_t fd;

    /*
     * Recycle: if the connection is keepalive, this flag is always on, but if
     * the caller wants to drop the connection once is released, it can set
     * recycle to false.
     */
    int recycle;

    /* Keepalive */
    int ka_count;        /* how many times this connection has been used */

    /*
     * Custom 'error' for the connection file descriptor. Commonly used to
     * specify a reason for an exception that was generated locally: consider
     * a connect timeout, we shutdown(2) the connection but in reallity we
     * might want to express an 'ETIMEDOUT'
     */
    int net_error;

    /* Timestamps */
    time_t ts_assigned;
    time_t ts_created;
    time_t ts_available;  /* sets the 'start' available time */

    /* Connect */
    time_t ts_connect_start;
    time_t ts_connect_timeout;

    /* Event loop */
    struct mk_event_loop *evl;

    /* Upstream parent */
    struct flb_upstream *u;

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

int flb_upstream_conn_recycle(struct flb_upstream_conn *conn, int val);
struct flb_upstream_conn *flb_upstream_conn_get(struct flb_upstream *u);
int flb_upstream_conn_release(struct flb_upstream_conn *u_conn);
int flb_upstream_conn_timeouts(struct mk_list *list);
int flb_upstream_conn_pending_destroy(struct flb_upstream *u);
int flb_upstream_conn_pending_destroy_list(struct mk_list *list);


#endif
