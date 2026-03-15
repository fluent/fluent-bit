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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pthread.h>
#include <string.h>

#include <fluent-bit/http_server/flb_http_server.h>
#include <fluent-bit/http_server/flb_http_server_config_map.h>

#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_gzip.h>

/* PRIVATE */

struct flb_http_server_worker_context {
    struct flb_http_server parent;
    struct flb_http_server server;
    struct flb_net_setup net_setup;
    struct mk_event_loop *event_loop;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int worker_id;
    int should_exit;
    int initialized;
    int thread_created;
    int startup_result;
};

struct flb_http_server_runtime {
    struct flb_http_server_worker_context *workers;
    int worker_count;
};

static void flb_http_server_runtime_stop(struct flb_http_server *session);

static void flb_http_server_worker_context_reset(
    struct flb_http_server_worker_context *worker)
{
    memset(worker, 0, sizeof(struct flb_http_server_worker_context));
    pthread_mutex_init(&worker->mutex, NULL);
    pthread_cond_init(&worker->condition, NULL);
}

static void flb_http_server_worker_context_cleanup(
    struct flb_http_server_worker_context *worker)
{
    pthread_mutex_destroy(&worker->mutex);
    pthread_cond_destroy(&worker->condition);
}

static int flb_http_server_running_on_caller_context(
    struct flb_http_server *session)
{
    return session->workers == 1 &&
           session->use_caller_event_loop == FLB_TRUE &&
           session->event_loop != NULL;
}

static const char *flb_http_server_get_alpn_string(struct flb_http_server *session)
{
    if (session == NULL) {
        return NULL;
    }

    if (session->protocol_version == HTTP_PROTOCOL_VERSION_AUTODETECT) {
        return "h2,http/1.1,http/1.0";
    }

    if (session->protocol_version >= HTTP_PROTOCOL_VERSION_20) {
        return "h2";
    }

    if (session->protocol_version == HTTP_PROTOCOL_VERSION_11) {
        return "http/1.1,http/1.0";
    }

    return "http/1.0";
}

static size_t flb_http_server_client_count(struct flb_http_server *server)
{
    return cfl_list_size(&server->clients);
}

static int flb_http_server_apply_options(struct flb_http_server *session,
                                         struct flb_http_server_options *options)
{
    if (session == NULL || options == NULL) {
        return -1;
    }

    session->status = HTTP_SERVER_UNINITIALIZED;
    session->protocol_version = options->protocol_version;
    session->flags = options->flags;
    session->request_callback = options->request_callback;
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
    session->buffer_chunk_size = options->buffer_chunk_size;
    session->max_connections = options->max_connections;
    session->workers = options->workers;
    session->worker_id = 0;
    session->use_caller_event_loop = options->use_caller_event_loop;
    session->reuse_port = options->reuse_port;
    session->tls_alpn_configured = FLB_FALSE;
    session->cb_worker_init = options->cb_worker_init;
    session->cb_worker_exit = options->cb_worker_exit;
    session->runtime = NULL;

    cfl_list_init(&session->clients);

    MK_EVENT_NEW(&session->listener_event);

    session->status = HTTP_SERVER_INITIALIZED;

    return 0;
}

static int flb_http_server_session_read(struct flb_http_server_session *session)
{
    size_t sent;
    size_t read_buffer_size;
    ssize_t result;
    char *request_too_large = "HTTP/1.1 413 Request Entity Too Large\r\n"
                              "Content-Length: 0\r\n"
                              "Connection: close\r\n\r\n";

    if (session->read_buffer == NULL) {
        if (session->parent != NULL &&
            session->parent->buffer_chunk_size > 0) {
            read_buffer_size = session->parent->buffer_chunk_size;
        }
        else {
            read_buffer_size = HTTP_SERVER_INITIAL_BUFFER_SIZE;
        }

        session->read_buffer = flb_malloc(read_buffer_size);
        if (session->read_buffer == NULL) {
            flb_errno();
            return -1;
        }

        session->read_buffer_size = read_buffer_size;
    }

    result = flb_io_net_read(session->connection,
                             (void *) session->read_buffer,
                             session->read_buffer_size);

    if (result <= 0) {
        return -1;
    }

    result = (ssize_t) flb_http_server_session_ingest(session,
                                                      session->read_buffer,
                                                      result);

    if (result == HTTP_SERVER_BUFFER_LIMIT_EXCEEDED) {
        flb_io_net_write(session->connection,
                         (void *) request_too_large,
                         strlen(request_too_large),
                         &sent);
        return -1;
    }
    else if (result < 0) {
        return -1;
    }

    return 0;
}

static int flb_http_server_session_write(struct flb_http_server_session *session)
{
    size_t data_length;
    size_t data_sent;
    int    result;

    if (session == NULL) {
        return -1;
    }

    if (session->outgoing_data == NULL) {
        return 0;
    }

    data_length = cfl_sds_len(session->outgoing_data);

    if (data_length > 0) {
        result = flb_io_net_write(session->connection,
                                  (void *) session->outgoing_data,
                                  data_length,
                                  &data_sent);

        if (result == -1) {
            return -2;
        }

        if (data_sent < data_length) {
            memmove(session->outgoing_data,
                    &session->outgoing_data[data_sent],
                    data_length - data_sent);

            cfl_sds_set_len(session->outgoing_data,
                            data_length - data_sent);
        }
        else {
            cfl_sds_set_len(session->outgoing_data, 0);
        }
    }

    return 0;
}

static int flb_http_server_should_connection_be_closed(
    struct flb_http_request *request)
{
    char                            *connection_header_value;
    struct flb_http_server_session  *parent_session;
    struct flb_downstream           *downstream;
    int                              keepalive;
    struct flb_http_server          *server;

    keepalive = FLB_FALSE;

    parent_session = (struct flb_http_server_session *) request->stream->parent;

    server = parent_session->parent;
    downstream = server->downstream;

    /* Version behaviors implemented in the following block :
     * HTTP/0.9 keep-alive is opt-in
     * HTTP/1.0 keep-alive is opt-in
     * HTTP/1.1 keep-alive is opt-out
     * HTTP/2   keep-alive is "mandatory"
     */

    if (request->protocol_version >= HTTP_PROTOCOL_VERSION_20) {
        /* HTTP/2 always keeps the connection open */
        return FLB_FALSE;
    }

    /*
      * user config overrides any protocol defaults, this is set
      * with the option 'net.keepalive: off`. This override is only
      * effective less than HTTP/2.
      */
    if (!downstream->net_setup->keepalive) {
        return FLB_TRUE;
    }

    /* Set the defaults per protocol version */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_09) {
        keepalive = FLB_FALSE;
    }
    else if (request->protocol_version == HTTP_PROTOCOL_VERSION_10) {
        keepalive = FLB_FALSE;
    }
    else if (request->protocol_version == HTTP_PROTOCOL_VERSION_11) {
        keepalive = FLB_TRUE;
    }

    /* Override protocol defaults by checking connection header */
    connection_header_value = flb_http_request_get_header(request,
                                                          "connection");
    if (connection_header_value &&
        strcasecmp(connection_header_value, "keep-alive") == 0) {
        keepalive = FLB_TRUE;
    }

    if (keepalive) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int flb_http_server_client_activity_event_handler(void *data)
{
    int                             close_connection;
    struct cfl_list                *backup_iterator;
    struct flb_connection          *connection;
    struct cfl_list                *iterator;
    struct flb_http_response       *response;
    struct flb_http_request        *request;
    struct flb_http_server_session *session;
    struct flb_http_server         *server;
    struct flb_http_stream         *stream;
    int                             result;
    struct mk_event                *event;

    connection = (struct flb_connection *) data;

    session = (struct flb_http_server_session *) connection->user_data;

    server = session->parent;

    event = &connection->event;

    if (event->mask & MK_EVENT_READ) {
        result = flb_http_server_session_read(session);

        if (result != 0) {
            flb_http_server_session_destroy(session);

            return -1;
        }
    }

    close_connection = FLB_FALSE;

    cfl_list_foreach_safe(iterator,
                            backup_iterator,
                            &session->request_queue) {
        request = cfl_list_entry(iterator, struct flb_http_request, _head);

        stream = (struct flb_http_stream *) request->stream;

        response = flb_http_response_begin(session, stream);

        if (request->body != NULL && request->content_length == 0) {
            request->content_length = cfl_sds_len(request->body);
        }

        if ((server->flags & FLB_HTTP_SERVER_FLAG_AUTO_INFLATE) != 0) {
            result = flb_http_request_uncompress_body(request);

            if (result != 0) {
                flb_http_server_session_destroy(session);

                return -1;
            }
        }

        if (server->request_callback != NULL) {
            result = server->request_callback(request, response);
        }
        else {
            /* Report */
        }

        close_connection = flb_http_server_should_connection_be_closed(request);

        flb_http_request_destroy(&stream->request);
        flb_http_response_destroy(&stream->response);
    }

    result = flb_http_server_session_write(session);

    if (result != 0) {
        flb_http_server_session_destroy(session);

        return -4;
    }

    if (close_connection) {
        flb_http_server_session_destroy(session);
    }

    return 0;
}

static int flb_http_server_client_connection_event_handler(void *data)
{
    struct flb_connection          *connection;
    struct flb_http_server_session *session;
    struct flb_http_server         *server;
    int                             result;

    server = (struct flb_http_server *) data;

    connection = flb_downstream_conn_get(server->downstream);

    if (connection == NULL) {
        return -1;
    }

    if (server->max_connections > 0 &&
        flb_http_server_client_count(server) >= server->max_connections) {
        flb_downstream_conn_release(connection);

        return -5;
    }

    session = flb_http_server_session_create(server->protocol_version);

    if (session == NULL) {
        flb_downstream_conn_release(connection);

        return -2;
    }

    session->parent = server;
    session->connection = connection;

    if (session->version <= HTTP_PROTOCOL_VERSION_11) {
        session->http1.stream.user_data = server->user_data;
    }

    MK_EVENT_NEW(&connection->event);

    connection->user_data     = (void *) session;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = flb_http_server_client_activity_event_handler;

    result = mk_event_add(server->event_loop,
                          connection->fd,
                          FLB_ENGINE_EV_CUSTOM,
                          MK_EVENT_READ,
                          &connection->event);

    if (result == -1) {
        flb_http_server_session_destroy(session);

        return -3;
    }

    cfl_list_add(&session->_head, &server->clients);

    result = flb_http_server_session_write(session);

    if (result != 0) {
        flb_http_server_session_destroy(session);

        return -4;
    }

    return 0;
}

static void flb_http_server_worker_maintenance(struct flb_config *config,
                                               void *data)
{
    struct flb_http_server_worker_context *worker;

    (void) config;

    worker = data;

    if (worker->server.downstream != NULL) {
        flb_downstream_conn_timeouts_stream(worker->server.downstream);
    }
}

static int flb_http_server_worker_initialize(
    struct flb_http_server_worker_context *worker)
{
    int result;
    struct flb_http_server_options options;

    flb_http_server_options_init(&options);

    options.protocol_version = worker->parent.protocol_version;
    options.flags = worker->parent.flags;
    options.request_callback = worker->parent.request_callback;
    options.user_data = worker->parent.user_data;
    options.address = worker->parent.address;
    options.port = worker->parent.port;
    options.tls_provider = worker->parent.tls_provider;
    options.networking_flags = worker->parent.networking_flags;
    options.networking_setup = &worker->net_setup;
    options.event_loop = worker->event_loop;
    options.system_context = worker->parent.system_context;
    options.buffer_max_size = worker->parent.buffer_max_size;
    options.workers = 1;
    options.use_caller_event_loop = FLB_TRUE;
    options.reuse_port = worker->parent.reuse_port;
    options.cb_worker_init = worker->parent.cb_worker_init;
    options.cb_worker_exit = worker->parent.cb_worker_exit;

    result = flb_http_server_init_with_options(&worker->server, &options);
    if (result != 0) {
        return result;
    }

    result = flb_http_server_start(&worker->server);
    if (result != 0) {
        return result;
    }

    flb_downstream_thread_safe(worker->server.downstream);

    worker->server.worker_id = worker->worker_id;
    worker->server.workers = worker->parent.workers;

    return 0;
}

static void *flb_http_server_worker_thread(void *data)
{
    int result;
    struct mk_event *event;
    struct flb_net_dns dns_ctx = {0};
    struct flb_http_server_worker_context *worker;

    worker = data;

    worker->event_loop = mk_event_loop_create(256);
    if (worker->event_loop == NULL) {
        result = -1;
        goto signal_and_exit;
    }

    flb_engine_evl_set(worker->event_loop);
    flb_net_ctx_init(&dns_ctx);
    flb_net_dns_ctx_set(&dns_ctx);

    result = flb_http_server_worker_initialize(worker);

signal_and_exit:
    pthread_mutex_lock(&worker->mutex);
    worker->startup_result = result;
    worker->initialized = FLB_TRUE;
    pthread_cond_signal(&worker->condition);
    pthread_mutex_unlock(&worker->mutex);

    if (result != 0) {
        goto cleanup;
    }

    while (worker->should_exit == FLB_FALSE) {
        mk_event_wait_2(worker->event_loop, 250);

        mk_event_foreach(event, worker->event_loop) {
            if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
        }

        flb_http_server_worker_maintenance(worker->parent.system_context,
                                           worker);
        flb_downstream_conn_pending_destroy(worker->server.downstream);
    }

cleanup:
    flb_http_server_destroy(&worker->server);

    if (worker->event_loop != NULL) {
        mk_event_loop_destroy(worker->event_loop);
        worker->event_loop = NULL;
    }

    return NULL;
}

static int flb_http_server_runtime_start(struct flb_http_server *session)
{
    const char *alpn;
    int index;
    int result;
    struct flb_http_server_runtime *runtime;

    runtime = flb_calloc(1, sizeof(struct flb_http_server_runtime));
    if (runtime == NULL) {
        flb_errno();
        return -1;
    }

    runtime->workers = flb_calloc(session->workers,
                                  sizeof(struct flb_http_server_worker_context));
    if (runtime->workers == NULL) {
        flb_errno();
        flb_free(runtime);
        return -1;
    }

    runtime->worker_count = session->workers;
    session->runtime = runtime;

    if (session->tls_provider != NULL &&
        session->tls_alpn_configured == FLB_FALSE) {
        alpn = flb_http_server_get_alpn_string(session);
        result = flb_tls_set_alpn(session->tls_provider, alpn);

        if (result != 0) {
            flb_free(runtime->workers);
            flb_free(runtime);
            session->runtime = NULL;

            return -1;
        }

        session->tls_alpn_configured = FLB_TRUE;
    }

    for (index = 0; index < runtime->worker_count; index++) {
        flb_http_server_worker_context_reset(&runtime->workers[index]);
        memcpy(&runtime->workers[index].parent,
               session,
               sizeof(struct flb_http_server));
        memcpy(&runtime->workers[index].net_setup,
               session->networking_setup,
               sizeof(struct flb_net_setup));

        runtime->workers[index].net_setup.share_port = FLB_TRUE;
        runtime->workers[index].worker_id = index;
        runtime->workers[index].parent.reuse_port = FLB_TRUE;
        runtime->workers[index].parent.runtime = NULL;
        runtime->workers[index].parent.workers = session->workers;

        result = pthread_create(&runtime->workers[index].thread,
                                NULL,
                                flb_http_server_worker_thread,
                                &runtime->workers[index]);
        if (result != 0) {
            runtime->workers[index].startup_result = -1;
            break;
        }
        runtime->workers[index].thread_created = FLB_TRUE;

        pthread_mutex_lock(&runtime->workers[index].mutex);
        while (runtime->workers[index].initialized == FLB_FALSE) {
            pthread_cond_wait(&runtime->workers[index].condition,
                              &runtime->workers[index].mutex);
        }
        result = runtime->workers[index].startup_result;
        pthread_mutex_unlock(&runtime->workers[index].mutex);

        if (result != 0) {
            break;
        }
    }

    if (index != runtime->worker_count) {
        flb_http_server_runtime_stop(session);
        return -1;
    }

    session->status = HTTP_SERVER_RUNNING;

    return 0;
}

static void flb_http_server_runtime_stop(struct flb_http_server *session)
{
    int index;
    struct flb_http_server_runtime *runtime;

    runtime = session->runtime;
    if (runtime == NULL) {
        return;
    }

    for (index = 0; index < runtime->worker_count; index++) {
        runtime->workers[index].should_exit = FLB_TRUE;

        if (runtime->workers[index].thread_created == FLB_TRUE) {
            pthread_join(runtime->workers[index].thread, NULL);
        }

        flb_http_server_worker_context_cleanup(&runtime->workers[index]);
    }

    flb_free(runtime->workers);
    flb_free(runtime);

    session->runtime = NULL;
}

/* HTTP SERVER */

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
    options->buffer_chunk_size = HTTP_SERVER_INITIAL_BUFFER_SIZE;
    options->max_connections = 0;
    options->workers = 1;
    options->use_caller_event_loop = FLB_TRUE;
    options->reuse_port = FLB_FALSE;
}

void flb_http_server_config_init(struct flb_http_server_config *config)
{
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(struct flb_http_server_config));

    config->http2 = FLB_TRUE;
    config->buffer_max_size = HTTP_SERVER_MAXIMUM_BUFFER_SIZE;
    config->buffer_chunk_size = HTTP_SERVER_INITIAL_BUFFER_SIZE;
    config->max_connections = 0;
    config->workers = 1;
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

int flb_input_http_server_options_init(struct flb_http_server_options *options,
                                       struct flb_input_instance *input_instance,
                                       uint64_t flags,
                                       flb_http_server_request_processor_callback request_callback,
                                       void *user_data)
{
    int protocol_version;
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
        if (server_config->buffer_chunk_size > 0) {
            options->buffer_chunk_size = server_config->buffer_chunk_size;
        }
        options->max_connections = server_config->max_connections;
        options->workers = server_config->workers;
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

    return flb_http_server_apply_options(session, options);
}

int flb_http_server_start(struct flb_http_server *session)
{
    const char *alpn;
    int result;

    if (!flb_http_server_running_on_caller_context(session)) {
        return flb_http_server_runtime_start(session);
    }

    if (session->tls_provider != NULL &&
        session->tls_alpn_configured == FLB_FALSE) {
        alpn = flb_http_server_get_alpn_string(session);
        result = flb_tls_set_alpn(session->tls_provider, alpn);

        if (result != 0) {
            return -1;
        }

        session->tls_alpn_configured = FLB_TRUE;
    }

    session->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                                session->networking_flags,
                                                session->address,
                                                session->port,
                                                session->tls_provider,
                                                session->system_context,
                                                session->networking_setup);

    if (session->downstream == NULL) {
        return -1;
    }

    session->listener_event.type    = FLB_ENGINE_EV_CUSTOM;
    session->listener_event.handler = flb_http_server_client_connection_event_handler;

    /* Register instance into the event loop */
    result = mk_event_add(session->event_loop,
                          session->downstream->server_fd,
                          FLB_ENGINE_EV_CUSTOM,
                          MK_EVENT_READ,
                          &session->listener_event);

    if (result == -1) {
        return -1;
    }

    if (session->cb_worker_init != NULL) {
        result = session->cb_worker_init(session,
                                         session->user_data);

        if (result != 0) {
            mk_event_del(session->event_loop, &session->listener_event);
            flb_downstream_destroy(session->downstream);
            session->downstream = NULL;

            return result;
        }
    }

    session->status = HTTP_SERVER_RUNNING;

    return 0;
}

int flb_http_server_stop(struct flb_http_server *server)
{
    struct cfl_list                *iterator_backup;
    struct cfl_list                *iterator;
    struct flb_http_server_session *session;

    if (server->runtime != NULL) {
        flb_http_server_runtime_stop(server);
        server->status = HTTP_SERVER_STOPPED;
        return 0;
    }

    if (server->status == HTTP_SERVER_RUNNING) {
        if (MK_EVENT_IS_REGISTERED((&server->listener_event))) {
            mk_event_del(server->event_loop, &server->listener_event);
        }

        mk_list_foreach_safe(iterator, iterator_backup, &server->clients) {
            session = cfl_list_entry(iterator,
                                     struct flb_http_server_session,
                                     _head);

            flb_http_server_session_destroy(session);
        }

        if (server->cb_worker_exit != NULL) {
            server->cb_worker_exit(server, server->user_data);
        }

        server->status = HTTP_SERVER_STOPPED;
    }

    return 0;
}

int flb_http_server_destroy(struct flb_http_server *server)
{
    flb_http_server_stop(server);

    if (server->downstream != NULL) {
        flb_downstream_destroy(server->downstream);

        server->downstream = NULL;
    }

    return 0;
}

int flb_http_server_init_on_input(struct flb_http_server *session,
                                  struct flb_input_instance *input_instance,
                                  int protocol_version,
                                  uint64_t flags,
                                  size_t buffer_max_size,
                                  flb_http_server_request_processor_callback request_callback,
                                  void *user_data)
{
    int result;
    struct flb_http_server_options options;

    if (session == NULL || input_instance == NULL) {
        return -1;
    }

    result = flb_http_server_options_init_from_input(&options,
                                                     input_instance,
                                                     protocol_version,
                                                     flags,
                                                     buffer_max_size,
                                                     request_callback,
                                                     user_data);
    if (result != 0) {
        return result;
    }

    result = flb_http_server_init_with_options(session, &options);

    if (result != 0) {
        return result;
    }

    result = flb_http_server_start(session);

    if (result != 0) {
        flb_http_server_destroy(session);
        return result;
    }

    result = 0;

    if (session->runtime == NULL && session->downstream != NULL) {
        result = flb_input_downstream_set(session->downstream, input_instance);

        if (result != 0) {
            flb_http_server_destroy(session);
        }
    }

    return result;
}

void flb_http_server_set_buffer_max_size(struct flb_http_server *server,
                                         size_t size)
{
    server->buffer_max_size = size;
}

size_t flb_http_server_get_buffer_max_size(struct flb_http_server *server)
{
    return server->buffer_max_size;
}

/* HTTP SESSION */

int flb_http_server_session_init(struct flb_http_server_session *session, int version)
{
    int result;

    memset(session, 0, sizeof(struct flb_http_server_session));

    cfl_list_init(&session->request_queue);
    cfl_list_entry_init(&session->_head);

    session->incoming_data = cfl_sds_create_size(HTTP_SERVER_INITIAL_BUFFER_SIZE);

    if (session->incoming_data == NULL) {
        return -1;
    }

    session->outgoing_data = cfl_sds_create_size(HTTP_SERVER_INITIAL_BUFFER_SIZE);

    if (session->outgoing_data == NULL) {
        return -2;
    }

    session->version = version;

    if (session->version == HTTP_PROTOCOL_VERSION_20) {
        result = flb_http2_server_session_init(&session->http2, session);

        if (result != 0) {
            return -3;
        }
    }
    else if (session->version >  HTTP_PROTOCOL_VERSION_AUTODETECT &&
             session->version <= HTTP_PROTOCOL_VERSION_11) {
        result = flb_http1_server_session_init(&session->http1, session);

        if (result != 0) {
            return -4;
        }
    }

    return 0;
}

struct flb_http_server_session *flb_http_server_session_create(int version)
{
    struct flb_http_server_session *session;
    int                  result;

    session = flb_calloc(1, sizeof(struct flb_http_server_session));

    if (session != NULL) {
        result = flb_http_server_session_init(session, version);

        session->releasable = FLB_TRUE;

        if (result != 0) {
            flb_http_server_session_destroy(session);

            session = NULL;
        }
    }

    return session;
}

void flb_http_server_session_destroy(struct flb_http_server_session *session)
{
    if (session != NULL) {
        if (session->connection != NULL) {
            flb_downstream_conn_release(session->connection);
        }

        if (!cfl_list_entry_is_orphan(&session->_head)) {
            cfl_list_del(&session->_head);
        }

        if (session->incoming_data != NULL) {
            cfl_sds_destroy(session->incoming_data);
        }

        if (session->outgoing_data != NULL) {
            cfl_sds_destroy(session->outgoing_data);
        }

        if (session->read_buffer != NULL) {
            flb_free(session->read_buffer);
        }

        flb_http1_server_session_destroy(&session->http1);
        flb_http2_server_session_destroy(&session->http2);

        if (session->releasable) {
            flb_free(session);
        }
    }
}

int flb_http_server_session_ingest(struct flb_http_server_session *session,
                            unsigned char *buffer,
                            size_t length)
{
    int       result;
    size_t    max_size;
    cfl_sds_t resized_buffer;

    max_size = flb_http_server_get_buffer_max_size(session->parent);
    if (session->parent != NULL && cfl_sds_len(session->incoming_data) + length > max_size) {
        return HTTP_SERVER_BUFFER_LIMIT_EXCEEDED;
    }

    if (session->version == HTTP_PROTOCOL_VERSION_AUTODETECT ||
        session->version <= HTTP_PROTOCOL_VERSION_11) {
        resized_buffer = cfl_sds_cat(session->incoming_data,
                                     (const char *) buffer,
                                     length);

        if (resized_buffer == NULL) {
            return HTTP_SERVER_ALLOCATION_ERROR;
        }

        session->incoming_data = resized_buffer;
    }

    if (session->version == HTTP_PROTOCOL_VERSION_AUTODETECT) {
        if (cfl_sds_len(session->incoming_data) >= 24) {
            if (strncmp(session->incoming_data,
                        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                        24) == 0) {
                session->version = HTTP_PROTOCOL_VERSION_20;
            }
            else {
                session->version = HTTP_PROTOCOL_VERSION_11;
            }
        }
        else if (cfl_sds_len(session->incoming_data) >= 4) {
            if (strncmp(session->incoming_data, "PRI ", 4) != 0) {
                session->version = HTTP_PROTOCOL_VERSION_11;
            }
        }

        if (session->version <= HTTP_PROTOCOL_VERSION_11) {
            result = flb_http1_server_session_init(&session->http1, session);

            if (result != 0) {
                return -1;
            }
        }
        else if (session->version == HTTP_PROTOCOL_VERSION_20) {
            result = flb_http2_server_session_init(&session->http2, session);

            if (result != 0) {
                return -1;
            }
        }
    }

    if (session->version <= HTTP_PROTOCOL_VERSION_11) {
        return flb_http1_server_session_ingest(&session->http1,
                                               buffer,
                                               length);
    }
    else if (session->version == HTTP_PROTOCOL_VERSION_20) {
        return flb_http2_server_session_ingest(&session->http2,
                                               buffer,
                                               length);
    }

    return -1;
}
