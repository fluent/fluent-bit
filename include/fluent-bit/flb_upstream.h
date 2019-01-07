/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_UPSTREAM_H
#define FLB_UPSTREAM_H

#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_config.h>

#ifdef FLB_HAVE_TLS
#include <mbedtls/net.h>
#endif
/*
 * Upstream creation FLAGS set by Fluent Bit sub-components
 * ========================================================
 *  Copyright (C) 2019      The Fluent Bit Authors
 *
 * --- flb_io.h ---
 *   #define  FLB_IO_TCP    1
 *   #define  FLB_IO_TLS    2
 *   #define  FLB_IO_ASYNC  8
 * ---
 */

/* Upstream handler */
struct flb_upstream {
    struct mk_event_loop *evl;

    int flags;
    int tcp_port;
    char *tcp_host;

    int n_connections;

    /*
     * An upstream handler may keep open up to 'max_connections' of
     * TCP connections. A value minor or equal to zero means it will
     * create a new connection on-demand if there is no one
     * available in the 'av_queue'.
     */
    int max_connections;

    /*
     * If an upstream context has been created in HA mode, this flag is
     * set to True and the field 'ha_ctx' will reference a HA upstream
     * context.
     */
    int ha_mode;
    void *ha_ctx;

    /*
     * This field is a linked-list-head for upstream connections that
     * are available for usage. When a connection is taken, it's moved to the
     * 'busy_queue' list.
     */
    struct mk_list av_queue;

    /*
     * Linked list head for upstream connections that are in use by some
     * plugin. When released, they are moved to the 'av_queue' list.
     */
    struct mk_list busy_queue;

#ifdef FLB_HAVE_TLS
    /* context with mbedTLS data to handle certificates and keys */
    struct flb_tls *tls;
#endif
};

/* Upstream TCP connection */
struct flb_upstream_conn {
    struct mk_event event;
    struct flb_thread *thread;

    flb_sockfd_t fd;
    int connect_count;

    /* Upstream parent */
    struct flb_upstream *u;

    /*
     * Link to list head on flb_upstream, if the connection is busy,
     * it's linked to 'busy_queue', otherwise it resides in 'av_queue'
     * so it can be used by a plugin.
     */
    struct mk_list _head;

#ifdef FLB_HAVE_TLS
    /* Each TCP connections using TLS needs a session */
    struct flb_tls_session *tls_session;
    mbedtls_net_context tls_net_context;
#endif

};

struct flb_upstream *flb_upstream_create(struct flb_config *config,
                                         char *host, int port, int flags,
                                         void *tls);
struct flb_upstream *flb_upstream_create_url(struct flb_config *config,
                                             char *url, int flags, void *tls);

int flb_upstream_destroy(struct flb_upstream *u);

struct flb_upstream_conn *flb_upstream_conn_get(struct flb_upstream *u);
int flb_upstream_conn_release(struct flb_upstream_conn *u_conn);

#endif
