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

#ifndef FLB_UPSTREAM_H
#define FLB_UPSTREAM_H

#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>

#ifdef FLB_HAVE_TLS
#include <mbedtls/net.h>
#endif

/*
 * Upstream creation FLAGS set by Fluent Bit sub-components
 * ========================================================
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *
 * --- flb_io.h ---
 *   #define  FLB_IO_TCP      1
 *   #define  FLB_IO_TLS      2
 *   #define  FLB_IO_ASYNC    8
 *   #define  FLB_IO_TCP_KA  16
 * ---
 */

/* Upstream handler */
struct flb_upstream {
    int flags;
    int tcp_port;
    char *tcp_host;
    int proxied_port;
    char *proxied_host;
    char *proxy_username;
    char *proxy_password;

    int n_connections;

    /* Networking setup for timeouts and network interfaces */
    struct flb_net_setup net;

    /*
     * If an upstream context has been created in HA mode, this flag is
     * set to True and the field 'ha_ctx' will reference a HA upstream
     * context.
     */
    int ha_mode;
    void *ha_ctx;

    /*
       If the connections will be in separate threads, this flag is
     * enabled and all lists management are protected through mutexes.
     */
    int thread_safe;
    pthread_mutex_t mutex_lists;

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

    struct mk_list destroy_queue;

#ifdef FLB_HAVE_TLS
    struct flb_tls *tls;
#endif

    struct mk_list _head;
};

struct flb_upstream *flb_upstream_create(struct flb_config *config,
                                         const char *host, int port, int flags,
                                         struct flb_tls *tls);
struct flb_upstream *flb_upstream_create_url(struct flb_config *config,
                                             const char *url, int flags,
                                             struct flb_tls *tls);

int flb_upstream_destroy(struct flb_upstream *u);

int flb_upstream_set_property(struct flb_config *config,
                              struct flb_net_setup *net, char *k, char *v);
int flb_upstream_is_async(struct flb_upstream *u);
void flb_upstream_thread_safe(struct flb_upstream *u);
struct mk_list *flb_upstream_get_config_map(struct flb_config *config);


#endif
