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
#include <string.h>

#include <fluent-bit/http_server/flb_http_server.h>

#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_gzip.h>

/* PRIVATE */

static int flb_http_server_session_read(struct flb_http_server_session *session)
{
    size_t sent;
    ssize_t result;
    unsigned char input_buffer[1024];
    char *request_too_large = "HTTP/1.1 413 Request Entity Too Large\r\n"
                              "Content-Length: 0\r\n"
                              "Connection: close\r\n\r\n";

    result = flb_io_net_read(session->connection,
                             (void *) &input_buffer,
                             sizeof(input_buffer));

    if (result <= 0) {
        return -1;
    }

    result = (ssize_t) flb_http_server_session_ingest(session,
                                                      input_buffer,
                                                      result);

    if (result == HTTP_SERVER_BUFFER_LIMIT_EXCEEDED) {
        flb_io_net_write(session->connection, (void *) request_too_large, strlen(request_too_large), &sent);
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

    session = flb_http_server_session_create(server->protocol_version);

    if (session == NULL) {
        flb_downstream_conn_release(connection);

        return -2;
    }

    session->parent = server;
    session->connection = connection;

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
                         void *user_data)
{
    session->status = HTTP_SERVER_UNINITIALIZED;
    session->protocol_version = protocol_version;
    session->flags = flags;
    session->request_callback = request_callback;
    session->user_data = user_data;

    session->address = address;
    session->port = port;
    session->tls_provider = tls_provider;
    session->networking_flags = networking_flags;
    session->networking_setup = networking_setup;
    session->event_loop = event_loop;
    session->system_context = system_context;

    session->downstream = NULL;
    session->buffer_max_size = HTTP_SERVER_MAXIMUM_BUFFER_SIZE;

    cfl_list_init(&session->clients);

    MK_EVENT_NEW(&session->listener_event);

    session->status = HTTP_SERVER_INITIALIZED;

    return 0;
}

int flb_http_server_start(struct flb_http_server *session)
{
    int result;

    if (session->tls_provider != NULL) {
        result = flb_tls_set_alpn(session->tls_provider, "h2,http/1.0,http/1.1");

        if (result != 0) {
            return -1;
        }
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

    session->status = HTTP_SERVER_RUNNING;

    return 0;
}

int flb_http_server_stop(struct flb_http_server *server)
{
    struct cfl_list                *iterator_backup;
    struct cfl_list                *iterator;
    struct flb_http_server_session *session;

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
