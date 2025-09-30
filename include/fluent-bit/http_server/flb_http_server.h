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

#ifndef FLB_HTTP_SERVER
#define FLB_HTTP_SERVER

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>

#include <monkey/mk_core.h>

#include <cfl/cfl_list.h>
#include <cfl/cfl_sds.h>

#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/http_server/flb_http_server_http1.h>
#include <fluent-bit/http_server/flb_http_server_http2.h>

#define HTTP_SERVER_INITIAL_BUFFER_SIZE        (10 * 1024)
#define HTTP_SERVER_MAXIMUM_BUFFER_SIZE        (10 * (1000 * 1024))

#define FLB_HTTP_SERVER_FLAG_KEEPALIVE         (((uint64_t) 1) << 0)
#define FLB_HTTP_SERVER_FLAG_AUTO_DEFLATE      (((uint64_t) 1) << 1)
#define FLB_HTTP_SERVER_FLAG_AUTO_INFLATE      (((uint64_t) 1) << 2)

#define HTTP_SERVER_SUCCESS                    0
#define HTTP_SERVER_PROVIDER_ERROR            -1
#define HTTP_SERVER_ALLOCATION_ERROR          -2
#define HTTP_SERVER_BUFFER_LIMIT_EXCEEDED     -3

#define HTTP_SERVER_UNINITIALIZED              0
#define HTTP_SERVER_INITIALIZED                1
#define HTTP_SERVER_RUNNING                    2
#define HTTP_SERVER_STOPPED                    3

typedef int (*flb_http_server_request_processor_callback)(
                struct flb_http_request *request,
                struct flb_http_response *response);

struct flb_http_server {
    /* Internal */
    struct mk_event        listener_event;
    char                  *address;
    unsigned short int     port;
    struct flb_tls        *tls_provider;
    int                    networking_flags;
    struct flb_net_setup  *networking_setup;
    struct mk_event_loop  *event_loop;
    struct flb_config     *system_context;
    /* Internal */

    uint64_t               flags;
    int                    status;
    int                    protocol_version;
    struct flb_downstream *downstream;
    struct cfl_list        clients;
    flb_http_server_request_processor_callback
                           request_callback;
    void                  *user_data;
    size_t                 buffer_max_size;
};

struct flb_http_server_session {
    struct flb_http1_server_session http1;
    struct flb_http2_server_session http2;

    int                             version;
    struct cfl_list                 request_queue;

    cfl_sds_t                       incoming_data;
    cfl_sds_t                       outgoing_data;

    int                             releasable;

    struct flb_connection          *connection;
    struct flb_http_server         *parent;
    struct cfl_list                 _head;
};

/* COMMON */



/* HTTP SERVER */

int flb_http_server_init(struct flb_http_server *session,
                         int protocol_version,
                         uint64_t flags,
                         flb_http_server_request_processor_callback
                             request_callback,
                         char *address,
                         unsigned short int port,
                         struct flb_tls *tls_provider,
                         int networking_flags,
                         struct flb_net_setup *networking_setup,
                         struct mk_event_loop *event_loop,
                         struct flb_config *system_context,
                         void *user_data);

int flb_http_server_start(struct flb_http_server *session);

int flb_http_server_stop(struct flb_http_server *session);

int flb_http_server_destroy(struct flb_http_server *session);

void flb_http_server_set_buffer_max_size(struct flb_http_server *server, size_t size);

size_t flb_http_server_get_buffer_max_size(struct flb_http_server *server);

/* HTTP SESSION */

int flb_http_server_session_init(struct flb_http_server_session *session, int version);

struct flb_http_server_session *flb_http_server_session_create(int version);

void flb_http_server_session_destroy(struct flb_http_server_session *session);

int flb_http_server_session_ingest(struct flb_http_server_session *session,
                            unsigned char *buffer,
                            size_t length);

#endif
