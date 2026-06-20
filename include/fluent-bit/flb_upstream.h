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

#ifndef FLB_UPSTREAM_H
#define FLB_UPSTREAM_H

#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_upstream_queue.h>
#include <fluent-bit/flb_stream.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>

/*
 * Upstream creation FLAGS set by Fluent Bit sub-components
 * ========================================================
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
    struct flb_stream          base;

    char                      *tcp_host;
    int                        tcp_port;

    char                      *proxied_host;
    int                        proxied_port;
    char                      *proxy_username;
    char                      *proxy_password;

    /*
     * If an upstream context has been created in HA mode, this flag is
     * set to True and the field 'ha_ctx' will reference a HA upstream
     * context.
     */
    int                        ha_mode;
    void                      *ha_ctx;

    struct cmt_gauge          *cmt_total_connections;
    struct cmt_gauge          *cmt_busy_connections;
    const char                *cmt_total_connections_label;
    const char                *cmt_busy_connections_label;

    /*
     * If the connections will be in separate threads, this flag is
     * enabled and all lists management are protected through mutexes.
     */
    void                     *parent_upstream;
    struct flb_upstream_queue queue;
};

static inline int flb_upstream_is_shutting_down(struct flb_upstream *u)
{
    return flb_stream_is_shutting_down(&u->base);
}

void flb_upstream_queue_init(struct flb_upstream_queue *uq);
struct flb_upstream_queue *flb_upstream_queue_get(struct flb_upstream *u);
void flb_upstream_list_set(struct mk_list *list);
struct mk_list *flb_upstream_list_get();

void flb_upstream_init();
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
int flb_upstream_needs_proxy(const char *host, const char *proxy, const char *no_proxy);

void flb_upstream_set_total_connections_label(
        struct flb_upstream *stream,
        const char *label_value);
void flb_upstream_set_total_connections_gauge(
        struct flb_upstream *stream,
        struct cmt_gauge *gauge_instance);

void flb_upstream_set_busy_connections_label(
        struct flb_upstream *stream,
        const char *label_value);
void flb_upstream_set_busy_connections_gauge(
        struct flb_upstream *stream,
        struct cmt_gauge *gauge_instance);

#endif
