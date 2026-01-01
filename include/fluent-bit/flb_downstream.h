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

#ifndef FLB_DOWNSTREAM_H
#define FLB_DOWNSTREAM_H

#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_stream.h>

struct flb_connection;

/* Downstream handler */
struct flb_downstream {
    struct flb_stream      base;

    char                  *host;
    unsigned short int     port;
    flb_sockfd_t           server_fd;
    struct flb_connection *dgram_connection;

    struct mk_list         busy_queue;
    struct mk_list         destroy_queue;

    /* this is a config map reference coming from the plugin net_setup field */
    struct flb_net_setup  *net_setup;

    /* pause state */
    int paused;
};

static inline int flb_downstream_is_shutting_down(struct flb_downstream *downstream)
{
    return flb_stream_is_shutting_down(&downstream->base);
}

void flb_downstream_init();

int flb_downstream_setup(struct flb_downstream *stream,
                         int transport, int flags,
                         const char *host,
                         unsigned short int port,
                         struct flb_tls *tls,
                         struct flb_config *config,
                         struct flb_net_setup *net_setup);

struct flb_downstream *flb_downstream_create(int transport, int flags,
                                             const char *host,
                                             unsigned short int port,
                                             struct flb_tls *tls,
                                             struct flb_config *config,
                                             struct flb_net_setup *net_setup);

void flb_downstream_destroy(struct flb_downstream *downstream);

int flb_downstream_set_property(struct flb_config *config,
                              struct flb_net_setup *net, char *k, char *v);

struct flb_connection *flb_downstream_conn_get(struct flb_downstream *stream);

void flb_downstream_pause(struct flb_downstream *stream);
void flb_downstream_resume(struct flb_downstream *stream);

int flb_downstream_conn_release(struct flb_connection *connection);

int flb_downstream_conn_pending_destroy_list(struct mk_list *list);

int flb_downstream_conn_timeouts(struct mk_list *list);

int flb_downstream_is_async(struct flb_downstream *downstream);

void flb_downstream_thread_safe(struct flb_downstream *stream);

struct mk_list *flb_downstream_get_config_map(struct flb_config *config);

#endif
