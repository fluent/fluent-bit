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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_engine.h>
#include <monkey/mk_core.h>

#include "http.h"
#include "http_conn.h"
#include "http_prot.h"

#define HTTP_SERVER_BUFFER_INITIAL_SIZE 1024

#define hex_dump(buffer, length, columns) __hex_dump__((char *) buffer, (size_t) length, (size_t) columns)

static void __hex_dump__(unsigned char *buffer, size_t length, size_t columns)
{
    int index;

    printf("\n\n");

    for (index = 0 ; index < length ; index++) {
        printf("%02x ", buffer[index]);
    }

    printf("\n\n");
}


static int http2_header_callback(nghttp2_session *inner_session,
                                 const nghttp2_frame *frame, 
                                 const uint8_t *name,
                                 size_t namelen, 
                                 const uint8_t *value,
                                 size_t valuelen, 
                                 uint8_t flags, 
                                 void *user_data);

static int caseless_compare_non_null_terminated_strings(char *first_buffer, 
                                                        size_t first_length,
                                                        char *second_buffer, 
                                                        size_t second_length);

static size_t parse_non_null_terminated_size_t(char *value, size_t length);

static int copy_non_null_terminated_string_to_mk_ptr(mk_ptr_t *destination, 
                                                     char *source_buffer, 
                                                     size_t source_length);

static void destroy_mk_ptr(mk_ptr_t *instance, int release_instance);

static struct mk_http_header *get_legacy_header(struct mk_http_parser *parser,
                                                int header_id);

static void destroy_legacy_header(struct mk_http_parser *parser,
                                  int header_id);

static void destroy_legacy_headers(struct mk_http_parser *parser);

static int insert_legacy_header(struct mk_http_parser *parser,
                                int header_id,
                                char *name_buffer, 
                                size_t name_length,
                                char *value_buffer, 
                                size_t value_length);

int http2_stream_init(struct http2_stream *stream,
                      struct http2_session *session, 
                      int32_t stream_id);

struct http2_stream *http2_stream_create(struct http2_session *session, 
                                         int32_t stream_id);

void http2_stream_destroy(struct http2_stream *stream);

int http2_stream_init(struct http2_stream *stream,
                      struct http2_session *session, 
                      int32_t stream_id)
{
    stream->id = stream_id;
    stream->status = HTTP2_STREAM_STATUS_RECEIVING_HEADERS;

    mk_http_parser_init(&stream->parser);

    mk_list_add(&stream->_head, &session->streams);

    return 0;
}

void http2_stream_destroy(struct http2_stream *stream)
{
    if (stream != NULL) {
        if (!mk_list_entry_is_orphan(&stream->_head)) {
            mk_list_del(&stream->_head);
        }

        destroy_legacy_headers(&stream->parser);

        destroy_mk_ptr(&stream->request.data, FLB_FALSE);

        flb_free(stream);
    }
}

struct http2_stream *http2_stream_create(struct http2_session *session, 
                                         int32_t stream_id) 
{
    struct http2_stream *stream;
    int                  result;

    stream = flb_calloc(1, sizeof(struct http2_stream));

    if (stream == NULL) {
        return NULL;
    }

    stream->releasable = FLB_TRUE;

    result = http2_stream_init(stream, session, stream_id);

    if (result != 0) {
        http2_stream_destroy(stream);
    }

    return stream;
}

static ssize_t http2_send_callback(nghttp2_session *inner_session, 
                                   const uint8_t *data,
                                   size_t length, 
                                   int flags, 
                                   void *user_data);

static ssize_t http2_recv_callback(nghttp2_session *inner_session, 
                                   const uint8_t *data,
                                   size_t length, 
                                   int flags, 
                                   void *user_data);

static ssize_t http2_send_callback(nghttp2_session *inner_session, 
                                   const uint8_t *data,
                                   size_t length, 
                                   int flags, 
                                   void *user_data)
{
    struct http2_session *session;
    int                   result;
    size_t                sent;

    session = (struct http2_session *) user_data;

    result = flb_io_net_write(session->parent->connection,
                              (void *) data,
                              length,
                              &sent);

    /* NGHTTP2_ERR_CALLBACK_FAILURE */

    return result;
}

static ssize_t http2_recv_callback(nghttp2_session *inner_session, 
                                   const uint8_t *data,
                                   size_t length, 
                                   int flags, 
                                   void *user_data)
{
    ssize_t               received;
    struct http2_session *session;
    int                   result;


    printf("RECVING UP TO %zu BYTES\n", length);

    session = (struct http2_session *) user_data;

    received = flb_io_net_read(session->parent->connection,
                               (void *) data,
                               length);
    
    printf("1 - RECEIVED = %zd\n", received);

    if (received == 0) {
        received = NGHTTP2_ERR_EOF;
    }
    else if (received < 0) {
        if (session->parent->connection->net_error == -1) {
            received = NGHTTP2_ERR_WOULDBLOCK;
        }
        else {
            received = NGHTTP2_ERR_CALLBACK_FAILURE;  
        }
    }

    printf("2 - RECEIVED = %zd\n", received);

    return received;
}

static int http2_frame_recv_callback(nghttp2_session *inner_session,
                                     const nghttp2_frame *frame, 
                                     void *user_data)
{
    struct http2_stream *stream;

    // if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
    //     return 0;
    // }

    stream = nghttp2_session_get_stream_user_data(inner_session, 
                                                  frame->hd.stream_id);

    if (stream == NULL) {
        return 0;
    }

    printf("STREAM %d RECEIVED FRAME TYPE %d\n", frame->hd.stream_id, frame->hd.type);

    switch (frame->hd.type) {
        case NGHTTP2_CONTINUATION:
        case NGHTTP2_HEADERS:

            if ((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) != 0) {
                stream->status = HTTP2_STREAM_STATUS_RECEIVING_DATA;
            }
            else {
                stream->status = HTTP2_STREAM_STATUS_RECEIVING_HEADERS;                
            }

            break;
        default:
            break;
    }
    
    return 0;
}

static int http2_stream_close_callback(nghttp2_session *session, 
                                       int32_t stream_id,
                                       uint32_t error_code, 
                                       void *user_data)
{
    struct http2_stream *stream;

    stream = nghttp2_session_get_stream_user_data(session, stream_id);

    if (stream == NULL) {
        return 0;
    }

    stream->status = HTTP2_STREAM_STATUS_CLOSED;

    return 0;
}

static int http2_begin_headers_callback(nghttp2_session *inner_session,
                                        const nghttp2_frame *frame,
                                        void *user_data) {
    struct http2_session *session;
    struct http2_stream  *stream;
    int                   result;

    session = (struct http2_session *) user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    stream = http2_stream_create(session, frame->hd.stream_id);

    if (stream == NULL) {
        return -1;
    }

    nghttp2_session_set_stream_user_data(inner_session,
                                         frame->hd.stream_id, 
                                         stream);

    return 0;
}


 static int *http2_data_chunk_recv_callback(nghttp2_session *inner_session, 
                                            uint8_t flags, 
                                            int32_t stream_id, 
                                            const uint8_t *data, 
                                            size_t len, 
                                            void *user_data)
 {
    struct http2_stream *stream;
    void                *resized_data;

    stream = nghttp2_session_get_stream_user_data(inner_session, stream_id);

    if (stream == NULL) {
        return 0;
    }

//     if (stream->status != HTTP2_STREAM_STATUS_RECEIVING_DATA) {
// printf("NOT YET RECEIVING DATA, DISCARDING %zu BYTES\n", len);
//         return 0;
//     }

printf("RECEIVING DATA CHUNK OF %zu BYTES\n", len);

    if (stream->request.data.data == NULL) {
        stream->request.data.data = flb_malloc(len);

        if (stream->request.data.data == NULL) {
            return -1;
        }

        memcpy(stream->request.data.data, data, len);

        stream->request.data.len = len;
    }
    else {
        resized_data = flb_realloc(stream->request.data.data, 
                                   stream->request.data.len + len);

        if (resized_data == NULL) {
            return -1;
        }

        stream->request.data.data = resized_data;

        memcpy(&stream->request.data.data[stream->request.data.len], 
               data,
               len);

        stream->request.data.len += len;

    }

printf("TOTAL RECEIVED : %zu\n", stream->request.data.len);

    // if (stream->content_length == stream->request.data.len) {
    //     stream->status = HTTP2_STREAM_STATUS_READY;
    // }
    // else if (stream->content_length < stream->request.data.len) {
    //     stream->status = HTTP2_STREAM_STATUS_ERROR;
    // }

    return 0;
 }


static int http2_header_callback(nghttp2_session *inner_session,
                                 const nghttp2_frame *frame, 
                                 const uint8_t *name,
                                 size_t namelen, 
                                 const uint8_t *value,
                                 size_t valuelen, 
                                 uint8_t flags, 
                                 void *user_data) 
{
    struct http2_stream *stream;
    int                  result;

    stream = nghttp2_session_get_stream_user_data(inner_session, 
                                                  frame->hd.stream_id);

    if (stream == NULL) {
        return 0;
    }

    printf("header_callback\n");
    printf("HEADER : %.*s\n", namelen, name);
    printf("VALUE  : %.*s\n", valuelen, value);
    printf("\n");

    if (caseless_compare_non_null_terminated_strings(name, 
                                                     namelen, 
                                                     ":method", 
                                                     strlen(":method")) == 0) {
        if (caseless_compare_non_null_terminated_strings(value, 
                                                         valuelen, 
                                                         "GET", 
                                                         strlen("GET")) == 0) {
            stream->request.method = MK_METHOD_GET;
        }
        else if (caseless_compare_non_null_terminated_strings(value, 
                                                              valuelen, 
                                                              "POST", 
                                                              strlen("POST")) == 0) {
            stream->request.method = MK_METHOD_POST;
        }
        else if (caseless_compare_non_null_terminated_strings(value, 
                                                              valuelen, 
                                                              "HEAD", 
                                                              strlen("HEAD")) == 0) {
            stream->request.method = MK_METHOD_HEAD;
        }
        else if (caseless_compare_non_null_terminated_strings(value, 
                                                              valuelen, 
                                                              "PUT", 
                                                              strlen("PUT")) == 0) {
            stream->request.method = MK_METHOD_PUT;
        }
        else if (caseless_compare_non_null_terminated_strings(value, 
                                                              valuelen, 
                                                              "DELETE", 
                                                              strlen("DELETE")) == 0) {
            stream->request.method = MK_METHOD_DELETE;
        }
        else if (caseless_compare_non_null_terminated_strings(value, 
                                                              valuelen, 
                                                              "OPTIONS", 
                                                              strlen("OPTIONS")) == 0) {
            stream->request.method = MK_METHOD_OPTIONS;
        }
        else if (caseless_compare_non_null_terminated_strings(value, 
                                                              valuelen, 
                                                              "SIZEOF", 
                                                              strlen("SIZEOF")) == 0) {
            stream->request.method = MK_METHOD_SIZEOF;
        }
        else {    
            stream->request.method = MK_METHOD_UNKNOWN;
        }
    }
    else if (caseless_compare_non_null_terminated_strings(name, 
                                                          namelen, 
                                                          ":path", 
                                                          strlen(":path")) == 0) {
        if (copy_non_null_terminated_string_to_mk_ptr(&stream->request.uri, 
                                                      value, 
                                                      valuelen) != 0) {
            return -1;
        }
    }
    else if (caseless_compare_non_null_terminated_strings(name, 
                                                          namelen, 
                                                          ":authority", 
                                                          strlen(":authority")) == 0) {
        if (copy_non_null_terminated_string_to_mk_ptr(&stream->request.host, 
                                                      value, 
                                                      valuelen) != 0) {
            return -1;
        }

        result = insert_legacy_header(&stream->parser, 
                                      MK_HEADER_HOST, 
                                      "host", 
                                      strlen("host"), 
                                      value, 
                                      valuelen);

        if (result != 0) {
            return -1;
        }
    }
    else if (caseless_compare_non_null_terminated_strings(name, 
                                                          namelen, 
                                                          ":scheme", 
                                                          strlen(":scheme")) == 0) {
        if (caseless_compare_non_null_terminated_strings(value, 
                                                         valuelen, 
                                                         "http", 
                                                         strlen("http")) == 0) {
            if (copy_non_null_terminated_string_to_mk_ptr(&stream->request.protocol_p, 
                                                          "HTTP/2", 
                                                          strlen("HTTP/2")) != 0) {
                return -1;
            }
        }
        else {
            if (copy_non_null_terminated_string_to_mk_ptr(&stream->request.protocol_p, 
                                                          value, 
                                                          valuelen) != 0) {
                return -1;
            }
        }
    }
    else if (caseless_compare_non_null_terminated_strings(name, 
                                                          namelen, 
                                                          "user-agent", 
                                                          strlen("user-agent")) == 0) {
        result = insert_legacy_header(&stream->parser, 
                                      MK_HEADER_USER_AGENT, 
                                      "user-agent", 
                                      strlen("user-agent"), 
                                      value, 
                                      valuelen);

        if (result != 0) {
            return -1;
        }
    }
    else if (caseless_compare_non_null_terminated_strings(name, 
                                                          namelen, 
                                                          "accept", 
                                                          strlen("accept")) == 0) {
        result = insert_legacy_header(&stream->parser, 
                                      MK_HEADER_ACCEPT, 
                                      "accept", 
                                      strlen("accept"), 
                                      value, 
                                      valuelen);

        if (result != 0) {
            return -1;
        }
    }
    else if (caseless_compare_non_null_terminated_strings(name, 
                                                          namelen, 
                                                          "content-length", 
                                                          strlen("content-length")) == 0) {
        result = insert_legacy_header(&stream->parser, 
                                      MK_HEADER_CONTENT_LENGTH, 
                                      "content-length", 
                                      strlen("content-length"), 
                                      value, 
                                      valuelen);

        if (result != 0) {
            return -1;
        }

        stream->content_length = parse_non_null_terminated_size_t(value, valuelen);

        printf("EXPECTED CONTENT LENGTH : %zu\n", stream->content_length);

    }
    else if (caseless_compare_non_null_terminated_strings(name, 
                                                          namelen, 
                                                          "content-type", 
                                                          strlen("content-type")) == 0) {
        result = insert_legacy_header(&stream->parser, 
                                      MK_HEADER_CONTENT_TYPE, 
                                      "content-type", 
                                      strlen("content-type"), 
                                      value, 
                                      valuelen);

        if (result != 0) {
            return -1;
        }
    }

    return 0;
}

static void dummy_mk_http_session_init(struct mk_http_session *session)
{
    session->_sched_init = MK_TRUE;
    session->pipelined   = MK_FALSE;
    session->counter_connections = 0;
    session->close_now = MK_FALSE;
    session->status = MK_REQUEST_STATUS_INCOMPLETE;
    session->server = NULL;
    session->socket = -1;

    /* creation time in unix time */
    session->init_time = time(NULL);

    /* Init session request list */
    mk_list_init(&session->request_list);

    /* Initialize the parser */
    mk_http_parser_init(&session->parser);
}


static int http1_session_init(struct http1_session *session)
{
    dummy_mk_http_session_init(&session->inner_session);

    mk_http_parser_init(&session->stream.parser);

    return 0;
}

static int http2_session_init(struct http2_session *session)
{
    nghttp2_session_callbacks *callbacks;
    int                        result;

    result = nghttp2_session_callbacks_new(&callbacks);

    if (result != 0) {
        return -1;
    }

    nghttp2_session_callbacks_set_send_callback(callbacks, http2_send_callback);

    nghttp2_session_callbacks_set_recv_callback(callbacks, http2_recv_callback);

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, http2_frame_recv_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, http2_stream_close_callback);

    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, http2_begin_headers_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, http2_data_chunk_recv_callback);

    nghttp2_session_callbacks_set_on_header_callback(callbacks, http2_header_callback);

    result = nghttp2_session_server_new(&session->inner_session, callbacks, session);

    nghttp2_session_callbacks_del(callbacks);

    if (result != 0) {
        return -2;
    }

    mk_list_init(&session->streams);

    return 0;
}

static int http_session_init(struct http_session *session, int version) {
    int result;

    memset(session, 0, sizeof(struct http_session));

    session->incoming_data_buffer = flb_calloc(1, HTTP_SERVER_BUFFER_INITIAL_SIZE);

    if (session->incoming_data_buffer == NULL) {
        return -1;
    }

    session->incoming_data_buffer_size = HTTP_SERVER_BUFFER_INITIAL_SIZE;
    session->incoming_data_buffer_used = 0;

    result = http1_session_init(&session->http1);

    if (result != 0) {
        return -2;
    }

    result = http2_session_init(&session->http2);

    if (result != 0) {
        return -3;
    }

    session->version = version;
    session->http1.parent = session;
    session->http2.parent = session;

    return 0;
}

static void http1_session_destroy(struct http1_session *session)
{
}

static void http2_session_destroy(struct http2_session *session)
{
    struct mk_list      *iterator_backup;
    struct mk_list      *iterator;
    struct http2_stream *stream;

    if (session != NULL) {
        mk_list_foreach_safe(iterator, 
                             iterator_backup, 
                             &session->streams) {
            stream = mk_list_entry(iterator, struct http2_stream, _head);

            http2_stream_destroy(stream);
        }

        nghttp2_session_del(session->inner_session);
    }
}

static void http_session_destroy(struct http_session *session)
{
    if (session != NULL) {
        if (session->incoming_data_buffer != NULL) {
            flb_free(session->incoming_data_buffer);
        }

        session->incoming_data_buffer_size = 0;
        session->incoming_data_buffer_used = 0;

        if (session->releasable) {
            flb_free(session);
        }
    }
}

static struct http_session *http_session_create(int version)
{
    struct http_session *session;
    int                  result;

    session = flb_calloc(1, sizeof(struct http_session));

    if (session != NULL) {
        session->releasable = FLB_TRUE;

        result = http_session_init(session, version);

        if (result != 0) {
            http_session_destroy(session);

            session = NULL;
        }
    }

    return session;
}

static void http2_conn_request_init(struct mk_http_session *session,
                                   struct mk_http_request *request);

static ssize_t data_source_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
  strcpy(buf, "PEDO");

  *data_flags |= NGHTTP2_DATA_FLAG_EOF;
   
  return 4;
}

static int send_response(nghttp2_session *session, struct http2_stream *stream) {
    int rv;
    nghttp2_data_provider data_prd;
    nghttp2_nv hdrs[] = {
                            ":status", 
                            "404",
                            strlen(":status"), 
                            strlen("404"),
                            NGHTTP2_NV_FLAG_NONE
                        };

    data_prd.source.fd = 0;
    data_prd.read_callback = data_source_read_callback;

    stream->status = HTTP2_STREAM_STATUS_PROCESSING;

    rv = nghttp2_submit_response(session, stream->id, hdrs, 1, &data_prd);

    if (rv != 0) {
        printf("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
    }

    stream->status = HTTP2_STREAM_STATUS_RECEIVING_HEADERS;

    return 0;
}

static int http2_conn_event(void *data)
{
    struct flb_connection *connection;
    struct http_conn *conn;
    struct mk_event *event;
    struct flb_http *ctx;
    int rv;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    event = &connection->event;

    if (event->mask & MK_EVENT_READ) {

#ifdef PEDORRO
        ssize_t readlen;
        ssize_t bytes;
        ssize_t available;
        static char buf_data[1024];
        int rv;

        available = sizeof(buf_data);

        bytes = flb_io_net_read(connection,
                                (void *) &buf_data,
                                available);

        if (bytes <= 0) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            http2_conn_del(conn);
            return -1;
        }

        readlen = nghttp2_session_mem_recv(conn->session_.http2.inner_session, buf_data, bytes);

        if (readlen < 0) {
            printf("Fatal error: %s", nghttp2_strerror((int)readlen));
            return -1;
        }

        printf("RECEIVED : %zu\n", (size_t) readlen);
#else
        conn->session_.data_signal = FLB_TRUE;

        rv = nghttp2_session_recv(conn->session_.http2.inner_session);

        if (rv == NGHTTP2_ERR_EOF) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            http2_conn_del(conn);
            return -1;
        }

        if (rv != 0) {
            printf("Fatal error: %s", nghttp2_strerror(rv));

            return -1;
        }
#endif
    }

    {
        struct mk_list *head;
        struct http2_stream *stream;

        mk_list_foreach(head, &conn->session_.http2.streams) {
            stream = mk_list_entry(head, struct http2_stream, _head);

            if (stream->content_length == stream->request.data.len) {
                stream->status = HTTP2_STREAM_STATUS_READY;
            }
            else if (stream->content_length < stream->request.data.len) {
                stream->status = HTTP2_STREAM_STATUS_ERROR;
            }

            printf("STREAM %d STATUS %d\n", stream->id, stream->status);

            if (stream->status == HTTP2_STREAM_STATUS_READY) {
                printf("REQUEST COMPLETO\n");

                if (stream->request.method == MK_METHOD_POST) {
                    printf("POST : %zu\n\n", stream->request.data.len);
                    {
                        int zz;

                        for (zz = 0 ; zz < stream->request.data.len ; zz++) {
                            printf("%c", stream->request.data.data[zz]);
                        }

                        printf("\n\n");
                    }
                }


                send_response(conn->session_.http2.inner_session, stream);
            }
        }
    }

    rv = nghttp2_session_send(conn->session_.http2.inner_session);
    if (rv != 0) {
        printf("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
    }


    return 0;
}

/*
static ssize_t recv_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data)
{
    struct flb_connection *connection;
    struct http_conn *conn;
    ssize_t bytes;

    conn = user_data;

    connection = conn->connection;

    bytes = flb_io_net_read(connection,
                            (void *) data,
                            length);

    return bytes;
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data)
{
    struct flb_connection *connection;
    struct http_conn *conn;
    struct mk_event *event;
    struct flb_http *ctx;
    size_t sent;
    int result;

    conn = user_data;

    connection = conn->connection;

    ctx = conn->ctx;

    event = &connection->event;

    result = flb_io_net_write(connection,
                             (void *) data,
                             length,
                             &sent);

    return result;
}
*/


struct http_conn *http2_conn_add(struct flb_connection *connection,
                                struct flb_http *ctx)
{
    struct http_conn *conn;
    int               ret;

    conn = flb_calloc(1, sizeof(struct http_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    mk_list_init(&conn->session_.http2.streams);

    conn->connection = connection;

    /* Set data for the event-loop */
    MK_EVENT_NEW(&connection->event);

    connection->user_data     = conn;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = http2_conn_event;

    /* Connection info */
    conn->ctx = ctx;

    /* Register instance into the event loop */
    ret = mk_event_add(flb_engine_evl_get(),
                       connection->fd,
                       FLB_ENGINE_EV_CUSTOM,
                       MK_EVENT_READ,
                       &connection->event);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");

        flb_free(conn);

        return NULL;
    }

    ret = http_session_init(&conn->session_, 2);

    if (ret != 0) {
        http_session_destroy(&conn->session_);

        return NULL;
    }

    conn->session_.connection = connection;

    /* Link connection node to parent context list */
    mk_list_add(&conn->_head, &ctx->connections);

{
    nghttp2_settings_entry iv[1] =  {
                                        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1}
                                    };
    int rv;

    rv = nghttp2_submit_settings(conn->session_.http2.inner_session, 
                                 NGHTTP2_FLAG_NONE, 
                                 iv,
                                 1);

printf("SEND SETTINGS RESULT : %d\n", rv);
    if (rv != 0) {
        printf("Fatal error: %s", nghttp2_strerror(rv));

        exit(0);
        return NULL;
    }

  rv = nghttp2_session_send(conn->session_.http2.inner_session);

    if (rv != 0) {
        printf("Fatal error: %s", nghttp2_strerror(rv));

        exit(0);
        return NULL;
    }

}


    return conn;
}

int http2_conn_del(struct http_conn *conn)
{
    /* The downstream unregisters the file descriptor from the event-loop
     * so there's nothing to be done by the plugin
     */
    flb_downstream_conn_release(conn->connection);

    mk_list_del(&conn->_head);

    http_session_destroy(&conn->session_);

    flb_free(conn);

    return 0;
}

void http2_conn_release_all(struct flb_http *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct http_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct http_conn, _head);
        http2_conn_del(conn);
    }
}

















static int caseless_compare_non_null_terminated_strings(char *first_buffer, 
                                                        size_t first_length,
                                                        char *second_buffer, 
                                                        size_t second_length)
{
    if (first_length < second_length) {
        return -1;
    }
    if (first_length > second_length) {
        return 1;
    }

    return strncasecmp(first_buffer, second_buffer, first_length);
}

static size_t parse_non_null_terminated_size_t(char *value, size_t length)
{
    char temporary_buffer[21];

    strncpy(temporary_buffer, value, length);

    return strtoull(temporary_buffer, NULL, 10);
}

static int copy_non_null_terminated_string_to_mk_ptr(mk_ptr_t *destination, 
                                                     char *source_buffer, 
                                                     size_t source_length)
{
    destination->data = flb_calloc(1, source_length);

    if (destination->data == NULL) {
        return -1;
    }

    destination->len = source_length;

    memcpy(destination->data, source_buffer, source_length);

    return 0;
}

static void destroy_mk_ptr(mk_ptr_t *instance, int release_instance)
{
    if (instance != NULL) {
        if (instance->data != NULL) {
            flb_free(instance->data);

            instance->data = NULL;
        }

        instance->len = 0;

        if (release_instance) {
            flb_free(instance);            
        }
    }
}

static struct mk_http_header *get_legacy_header(struct mk_http_parser *parser,
                                                int header_id)
{
    struct mk_http_header *header;

    header = NULL;

    if (parser != NULL) {
        if (header_id >= MK_HEADER_ACCEPT && 
            header_id <= MK_HEADER_SIZEOF) {

            header = &parser->headers[header_id];
        }
        else {
            if (parser->headers_extra_count > MK_HEADER_EXTRA_SIZE) {
                header = &parser->headers_extra[header_id - MK_HEADER_SIZEOF];
            }
        }
    }

    return header;
}

static void destroy_legacy_header(struct mk_http_parser *parser,
                                  int header_id) 
{
    struct mk_http_header *header;

    if (parser != NULL) {
        header = get_legacy_header(parser, header_id);

        if (header != NULL) {
            destroy_mk_ptr(&header->key, FLB_FALSE);
            destroy_mk_ptr(&header->val, FLB_FALSE);

            if (header_id > MK_HEADER_SIZEOF) {
                parser->headers_extra_count--;
            }
        }
    }
}

static int insert_legacy_header(struct mk_http_parser *parser,
                                int header_id,
                                char *name_buffer, 
                                size_t name_length,
                                char *value_buffer, 
                                size_t value_length)
{
    struct mk_http_header *header;
    int                    result;

    header = get_legacy_header(parser, header_id);

    if (header == NULL) {
        return -1;
    }

    result = copy_non_null_terminated_string_to_mk_ptr(&header->key, 
                                                       name_buffer, 
                                                       name_length);

    if (result != 0) {
        return -2;
    }

    result = copy_non_null_terminated_string_to_mk_ptr(&header->val,
                                                       value_buffer,
                                                       value_length);

    if (result != 0) {
        destroy_mk_ptr(&header->key, FLB_FALSE);

        return -3;
    }

    if (header_id > MK_HEADER_SIZEOF) {
        parser->headers_extra_count++;
    }

    return 0;
}

static void destroy_legacy_headers(struct mk_http_parser *parser)
{
    size_t header_index;

    while (parser->headers_extra_count > 0) {
        header_index = MK_HEADER_SIZEOF + parser->headers_extra_count;

        destroy_legacy_header(parser, header_index);
    }

    for (header_index = MK_HEADER_ACCEPT ; 
         header_index < MK_HEADER_SIZEOF ; 
         header_index++) {
        destroy_legacy_header(parser, header_index);
    }
} 

