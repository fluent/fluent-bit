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

#include <fluent-bit/http_server/flb_http_server.h>

#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_gzip.h>

static \
int uncompress_zlib(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

static \
int uncompress_zstd(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

static \
int uncompress_deflate(char **output_buffer,
                       size_t *output_size,
                       char *input_buffer,
                       size_t input_size);

static \
int uncompress_snappy(char **output_buffer,
                      size_t *output_size,
                      char *input_buffer,
                      size_t input_size);

static \
int uncompress_gzip(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

/* COMMON */

char *flb_http_server_convert_string_to_lowercase(char *input_buffer,
                                                  size_t length)
{
    char  *output_buffer;
    size_t index;

    output_buffer = flb_calloc(1, length + 1);

    if (output_buffer != NULL) {
        for (index = 0 ; index < length ; index++) {
            output_buffer[index] = tolower(input_buffer[index]);
        }

    }

    return output_buffer;
}


int flb_http_server_strncasecmp(const uint8_t *first_buffer,
                                size_t first_length,
                                const char *second_buffer,
                                size_t second_length)
{
    const char *first_buffer_;
    const char *second_buffer_;

    first_buffer_  = (const char *) first_buffer;
    second_buffer_ = (const char *) second_buffer;

    if (first_length == 0) {
        first_length = strlen(first_buffer_);
    }

    if (second_length == 0) {
        second_length = strlen(second_buffer_);
    }

    if (first_length < second_length) {
        return -1;
    }
    else if (first_length > second_length) {
        return 1;
    }

    return strncasecmp(first_buffer_, second_buffer_, first_length);
}





/* PRIVATE */

static int flb_http_server_session_read(struct flb_http_server_session *session)
{
    unsigned char input_buffer[1024];
    ssize_t result;

    result = flb_io_net_read(session->connection,
                             (void *) &input_buffer,
                             sizeof(input_buffer));

    if (result <= 0) {
        return -1;
    }

    result = (ssize_t) flb_http_server_session_ingest(session,
                                                      input_buffer,
                                                      result);

    if (result < 0) {
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



static int flb_http_server_inflate_request_body(
    struct flb_http_request *request)
{
    char                            *content_encoding_header_value;
    char                             new_content_length[21];
    struct flb_http_server_session  *parent_session;
    cfl_sds_t                        inflated_body;
    char                            *output_buffer;
    size_t                           output_size;
    struct flb_http_server          *server;
    int                              result;

    parent_session = (struct flb_http_server_session *) request->stream->parent;

    server = parent_session->parent;
    result = 0;

    if (request->body == NULL) {
        return 0;
    }

    if ((server->flags & FLB_HTTP_SERVER_FLAG_AUTO_INFLATE) == 0) {
        return 0;
    }

    content_encoding_header_value = flb_http_request_get_header(
                                        request,
                                        "content-encoding");

    if (content_encoding_header_value == NULL) {
        return 0;
    }

    if (strncasecmp(content_encoding_header_value, "gzip", 4) == 0) {
        result = uncompress_gzip(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zlib", 4) == 0) {
        result = uncompress_zlib(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zstd", 4) == 0) {
        result = uncompress_zstd(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "snappy", 6) == 0) {
        result = uncompress_snappy(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "deflate", 4) == 0) {
        result = uncompress_deflate(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }

    if (result == 1) {
        inflated_body = cfl_sds_create_len(output_buffer, output_size);

        flb_free(output_buffer);

        if (inflated_body == NULL) {
            return -1;
        }

        cfl_sds_destroy(request->body);

        request->body = inflated_body;

        snprintf(new_content_length,
                 sizeof(new_content_length),
                 "%zu",
                 output_size);

        flb_http_request_unset_header(request, "content-encoding");
        flb_http_request_set_header(request,
                                    "content-length", strlen("content-length"),
                                    new_content_length, strlen(new_content_length));

        request->content_length = output_size;
    }

    return 0;
}

static int flb_http_server_should_connection_be_closed(
    struct flb_http_request *request)
{
    int keepalive = FLB_FALSE;
    char *connection_header_value;
    struct flb_http_server_session  *parent_session;
    struct flb_http_server          *server;
    struct flb_downstream *downstream;

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

        result = flb_http_server_inflate_request_body(request);

        if (result != 0) {
            flb_http_server_session_destroy(session);

            return -1;
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

    if (session->version == HTTP_PROTOCOL_HTTP2) {
        result = flb_http2_server_session_init(&session->http2, session);

        if (result != 0) {
            return -3;
        }
    }
    else if (session->version == HTTP_PROTOCOL_HTTP1) {
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
    cfl_sds_t resized_buffer;
    int       result;

    if (session->version == HTTP_PROTOCOL_AUTODETECT ||
        session->version == HTTP_PROTOCOL_HTTP1) {
        resized_buffer = cfl_sds_cat(session->incoming_data,
                                     (const char *) buffer,
                                     length);

        if (resized_buffer == NULL) {
            return HTTP_SERVER_ALLOCATION_ERROR;
        }

        session->incoming_data = resized_buffer;
    }

    if (session->version == HTTP_PROTOCOL_AUTODETECT) {
        if (cfl_sds_len(session->incoming_data) >= 24) {
            if (strncmp(session->incoming_data,
                        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                        24) == 0) {
                session->version = HTTP_PROTOCOL_HTTP2;
            }
            else {
                session->version = HTTP_PROTOCOL_HTTP1;
            }
        }
        else if (cfl_sds_len(session->incoming_data) >= 4) {
            if (strncmp(session->incoming_data, "PRI ", 4) != 0) {
                session->version = HTTP_PROTOCOL_HTTP1;
            }
        }

        if (session->version == HTTP_PROTOCOL_HTTP1) {
            result = flb_http1_server_session_init(&session->http1, session);

            if (result != 0) {
                return -1;
            }
        }
        else if (session->version == HTTP_PROTOCOL_HTTP2) {
            result = flb_http2_server_session_init(&session->http2, session);

            if (result != 0) {
                return -1;
            }
        }
    }

    if (session->version == HTTP_PROTOCOL_HTTP1) {
        return flb_http1_server_session_ingest(&session->http1,
                                               buffer,
                                               length);
    }
    else if (session->version == HTTP_PROTOCOL_HTTP2) {
        return flb_http2_server_session_ingest(&session->http2,
                                               buffer,
                                               length);
    }

    return -1;
}


/* PRIVATE */

static \
int uncompress_zlib(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    return 0;
}

static \
int uncompress_zstd(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    return 0;
}

static \
int uncompress_deflate(char **output_buffer,
                       size_t *output_size,
                       char *input_buffer,
                       size_t input_size)
{
    return 0;
}

static \
int uncompress_snappy(char **output_buffer,
                      size_t *output_size,
                      char *input_buffer,
                      size_t input_size)
{
    int ret;

    ret = flb_snappy_uncompress_framed_data(input_buffer,
                                            input_size,
                                            output_buffer,
                                            output_size);

    if (ret != 0) {
        flb_error("[opentelemetry] snappy decompression failed");

        return -1;
    }

    return 1;
}

static \
int uncompress_gzip(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    int ret;

    ret = flb_gzip_uncompress(input_buffer,
                              input_size,
                              (void *) output_buffer,
                              output_size);

    if (ret == -1) {
        flb_error("[opentelemetry] gzip decompression failed");

        return -1;
    }

    return 1;
}

