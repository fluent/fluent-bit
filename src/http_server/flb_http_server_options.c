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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/http_server/flb_http_server.h>
#include <fluent-bit/http_server/flb_http_server_config_map.h>

#include <cfl/cfl_atomic.h>

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Server options and initialization. Nothing here touches a socket, so this
 * file is also part of builds that have no listener, where requests are
 * supplied by the host program.
 */

static int flb_http_server_apply_options(struct flb_http_server *session,
                                         struct flb_http_server_options *options)
{
    if (session == NULL || options == NULL) {
        return -1;
    }

    session->status = HTTP_SERVER_UNINITIALIZED;
    session->protocol_version = options->protocol_version;
    session->idle_timeout = options->idle_timeout;
    session->flags = options->flags;
    session->request_callback = options->request_callback;
    session->authorization_callback = options->authorization_callback;
    session->user_data = options->user_data;

    session->address = options->address;
    session->port = options->port;
    session->tls_provider = options->tls_provider;
    session->networking_flags = options->networking_flags;
    session->networking_setup = options->networking_setup;
    session->event_loop = options->event_loop;
    session->system_context = options->system_context;

    session->downstream = NULL;
    session->buffer_max_size = options->buffer_max_size;
    session->max_decoded_body_size = options->max_decoded_body_size;
    session->http1_max_header_size = options->http1_max_header_size;
    session->buffer_chunk_size = options->buffer_chunk_size;
    session->max_connections = options->max_connections;
    cfl_atomic_store(&session->active_connections, 0);
    if (options->connection_counter != NULL) {
        session->connection_counter = options->connection_counter;
    }
    else {
        session->connection_counter = &session->active_connections;
    }
    session->workers = options->workers;
    session->host_driven = options->host_driven;
    session->worker_id = 0;
    session->managed_worker = FLB_FALSE;
    session->use_caller_event_loop = options->use_caller_event_loop;
    session->reuse_port = options->reuse_port;
    session->tls_alpn_configured = FLB_FALSE;
    session->cb_worker_init = options->cb_worker_init;
    session->cb_worker_exit = options->cb_worker_exit;
    session->runtime = NULL;
    session->balancer = NULL;
    session->handoff = NULL;

    cfl_list_init(&session->clients);
    cfl_list_init(&session->detached_clients);

    MK_EVENT_NEW(&session->listener_event);

    session->status = HTTP_SERVER_INITIALIZED;

    return 0;
}

int flb_http_server_init(struct flb_http_server *session,
                         int protocol_version,
                         uint64_t flags,
                         flb_http_server_request_processor_callback request_callback,
                         char *address,
                         unsigned short int port,
                         struct flb_tls *tls_provider,
                         int networking_flags,
                         struct flb_net_setup *networking_setup,
                         struct mk_event_loop *event_loop,
                         struct flb_config *system_context,
                         void *user_data)
{
    struct flb_http_server_options options;

    flb_http_server_options_init(&options);

    options.protocol_version = protocol_version;
    options.flags = flags;
    options.request_callback = request_callback;
    options.user_data = user_data;
    options.address = address;
    options.port = port;
    options.tls_provider = tls_provider;
    options.networking_flags = networking_flags;
    options.networking_setup = networking_setup;
    options.event_loop = event_loop;
    options.system_context = system_context;

    return flb_http_server_init_with_options(session, &options);
}

void flb_http_server_options_init(struct flb_http_server_options *options)
{
    if (options == NULL) {
        return;
    }

    memset(options, 0, sizeof(struct flb_http_server_options));

    options->buffer_max_size = HTTP_SERVER_MAXIMUM_BUFFER_SIZE;
    options->max_decoded_body_size = HTTP_SERVER_DEFAULT_MAX_DECODED_BODY_SIZE;
    options->http1_max_header_size = HTTP_SERVER_DEFAULT_HTTP1_MAX_HEADER_SIZE;
    options->buffer_chunk_size = HTTP_SERVER_INITIAL_BUFFER_SIZE;
    options->idle_timeout = HTTP_SERVER_DEFAULT_IDLE_TIMEOUT;
    options->max_connections = 0;
    options->workers = 1;
    options->use_caller_event_loop = FLB_TRUE;
    options->reuse_port = FLB_FALSE;
}

int flb_http_server_options_init_from_input(struct flb_http_server_options *options,
                                            struct flb_input_instance *input_instance,
                                            int protocol_version,
                                            uint64_t flags,
                                            size_t buffer_max_size,
                                            flb_http_server_request_processor_callback
                                                request_callback,
                                            void *user_data)
{
    if (options == NULL || input_instance == NULL) {
        return -1;
    }

    flb_http_server_options_init(options);

    options->protocol_version = protocol_version;
    options->flags = flags;
    options->request_callback = request_callback;
    options->user_data = user_data;
    options->address = input_instance->host.listen;
    options->port = input_instance->host.port;
    options->tls_provider = input_instance->tls;
    options->networking_flags = input_instance->flags;
    options->networking_setup = &input_instance->net_setup;
    options->event_loop = flb_input_event_loop_get(input_instance);
    options->system_context = input_instance->config;
    options->buffer_max_size = buffer_max_size;
    options->buffer_chunk_size = HTTP_SERVER_INITIAL_BUFFER_SIZE;
    options->max_connections = 0;
    options->reuse_port = input_instance->net_setup.share_port;

    return 0;
}

/* The binary-size helper accepts numeric prefixes; require a complete value here. */
static int http_server_header_size_is_valid(const char *value)
{
    char *suffix;

    strtod(value, &suffix);
    if (suffix == value) {
        return FLB_FALSE;
    }

    return *suffix == '\0' ||
           strcasecmp(suffix, "K") == 0 || strcasecmp(suffix, "KB") == 0 ||
           strcasecmp(suffix, "KiB") == 0 ||
           strcasecmp(suffix, "M") == 0 || strcasecmp(suffix, "MB") == 0 ||
           strcasecmp(suffix, "MiB") == 0 ||
           strcasecmp(suffix, "G") == 0 || strcasecmp(suffix, "GB") == 0 ||
           strcasecmp(suffix, "GiB") == 0;
}

int flb_input_http_server_options_init(struct flb_http_server_options *options,
                                       struct flb_input_instance *input_instance,
                                       uint64_t flags,
                                       flb_http_server_request_processor_callback request_callback,
                                       void *user_data)
{
    int protocol_version;
    int64_t header_limit;
    size_t buffer_max_size;
    int result;
    struct flb_http_server_config *server_config;

    if (input_instance == NULL || options == NULL ||
        input_instance->http_server_config == NULL) {
        return -1;
    }

    server_config = input_instance->http_server_config;

    if (server_config != NULL && server_config->http2 == FLB_FALSE) {
        protocol_version = HTTP_PROTOCOL_VERSION_11;
    }
    else {
        protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    }

    if (server_config != NULL && server_config->buffer_max_size > 0) {
        buffer_max_size = server_config->buffer_max_size;
    }
    else {
        buffer_max_size = HTTP_SERVER_MAXIMUM_BUFFER_SIZE;
    }

    result = flb_http_server_options_init_from_input(options,
                                                     input_instance,
                                                     protocol_version,
                                                     flags,
                                                     buffer_max_size,
                                                     request_callback,
                                                     user_data);
    if (result != 0) {
        return result;
    }

    if (server_config != NULL) {
        options->idle_timeout = server_config->idle_timeout;
        options->max_decoded_body_size = server_config->max_decoded_body_size;
        if (server_config->http1_max_header_size != NULL) {
            if (!http_server_header_size_is_valid(server_config->http1_max_header_size)) {
                flb_error("[http_server] invalid http_server.http1_max_header_size");
                return -1;
            }
            header_limit = flb_utils_size_to_binary_bytes(server_config->http1_max_header_size);
            if (header_limit < 0 || (uint64_t) header_limit > SIZE_MAX) {
                flb_error("[http_server] invalid http_server.http1_max_header_size");
                return -1;
            }
            if (header_limit > 0) {
                options->http1_max_header_size = (size_t) header_limit;
            }
        }
        if (server_config->buffer_chunk_size > 0) {
            options->buffer_chunk_size = server_config->buffer_chunk_size;
        }
        options->max_connections = server_config->max_connections;
        options->workers = server_config->workers;
    }

    if (flb_input_is_external(input_instance)) {
        /* Requests come from the host program: there is nothing to listen on */
        if (options->workers > 1) {
            flb_error("[http_server] 'http_server.workers' cannot be used with "
                      "source.mode 'external'");
            return -1;
        }
        options->host_driven = FLB_TRUE;
    }

    return 0;
}

int flb_http_server_init_with_options(
    struct flb_http_server *session,
    struct flb_http_server_options *options)
{
    if (session == NULL || options == NULL) {
        return -1;
    }

    if (options->buffer_max_size == 0) {
        options->buffer_max_size = HTTP_SERVER_MAXIMUM_BUFFER_SIZE;
    }

    if (options->max_decoded_body_size == 0) {
        options->max_decoded_body_size = HTTP_SERVER_DEFAULT_MAX_DECODED_BODY_SIZE;
    }
    else if (options->max_decoded_body_size == SIZE_MAX) {
        flb_error("[http server] invalid http_server.max_decoded_body_size");
        return -1;
    }

    if (options->http1_max_header_size == 0) {
        options->http1_max_header_size = HTTP_SERVER_DEFAULT_HTTP1_MAX_HEADER_SIZE;
    }

    if (options->workers <= 0) {
        options->workers = 1;
    }

    if (options->workers > 1) {
        options->reuse_port = FLB_TRUE;
        options->use_caller_event_loop = FLB_FALSE;
    }

    if (options->reuse_port == FLB_TRUE &&
        options->networking_setup != NULL) {
        options->networking_setup->share_port = FLB_TRUE;
    }

    if (options->networking_setup != NULL &&
        options->networking_setup->io_timeout <= 0 &&
        options->idle_timeout > 0) {
        options->networking_setup->io_timeout = options->idle_timeout;
    }

    return flb_http_server_apply_options(session, options);
}
