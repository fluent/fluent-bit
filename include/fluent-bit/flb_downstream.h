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

#ifndef FLB_DOWNSTREAM_H
#define FLB_DOWNSTREAM_H

#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>

#ifdef FLB_HAVE_TLS
#endif

/*
 * Downstream creation FLAGS set by Fluent Bit sub-components
 * ========================================================
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *
 * --- flb_io.h ---
 *   #define  FLB_IO_TCP      1
 *   #define  FLB_IO_TLS      2
 *   #define  FLB_IO_ASYNC    8
 * ---
 */

/* Downstream handler */
struct flb_downstream {
    struct mk_event event;
    int flags;
    unsigned short int port;
    char *host;

    flb_sockfd_t server_fd;

    /* Networking setup for timeouts and network interfaces */
    struct flb_net_setup net;

    int thread_safe;
    pthread_mutex_t mutex_lists;

    void *parent_downstream;

#ifdef FLB_HAVE_TLS
    struct flb_tls *tls;
#endif
    int dynamically_allocated;

    struct mk_list busy_queue;
    struct mk_list destroy_queue;

    struct flb_config *config;
    struct mk_list _head;
};


static inline int flb_downstream_is_shutting_down(struct flb_downstream *downstream)
{
    return downstream->config->is_shutting_down;
}

void flb_downstream_init();

int flb_downstream_setup(struct flb_downstream *stream,
                         struct flb_config *config,
                         const char *host, const char *port,
                         int flags, struct flb_tls *tls);

struct flb_downstream *flb_downstream_create(struct flb_config *config,
                                             const char *host, const char *port,
                                             int flags, struct flb_tls *tls);

void flb_downstream_destroy(struct flb_downstream *downstream);

int flb_downstream_set_property(struct flb_config *config,
                              struct flb_net_setup *net, char *k, char *v);

int flb_downstream_is_async(struct flb_downstream *downstream);

struct mk_list *flb_downstream_get_config_map(struct flb_config *config);

#endif
