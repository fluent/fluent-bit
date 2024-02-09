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

// #pragma GCC diagnostic error "-Wall"

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

int http2_conn_flush_session(struct http_session *session);

static ssize_t http2_send_callback(nghttp2_session *inner_session, 
                                   const uint8_t *data,
                                   size_t length, 
                                   int flags, 
                                   void *user_data);


static int http2_header_callback(nghttp2_session *inner_session,
                                 const nghttp2_frame *frame, 
                                 const uint8_t *name,
                                 size_t namelen, 
                                 const uint8_t *value,
                                 size_t valuelen, 
                                 uint8_t flags, 
                                 void *user_data);

static int http2_strncasecmp(const uint8_t *first_buffer, 
                             size_t first_length,
                             const char *second_buffer, 
                             size_t second_length);

static inline size_t http2_lower_value(size_t left_value, size_t right_value) 
{
    if (left_value < right_value) {
        return left_value;
    }

    return right_value;
}

int http_stream_init(struct http_stream *stream,
                     struct http_session *session, 
                     int32_t stream_id);

struct http_stream *http_stream_create(struct http_session *session, 
                                       int32_t stream_id);

void http_stream_destroy(struct http_stream *stream);

static void http_response_destroy(struct http_response *response);

static int http_response_init(struct http_response *response);

static void http_request_destroy(struct http_request *request);

static int http_request_init(struct http_request *request);

static char *convert_string_to_lowercase(char *input_buffer, size_t length)
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

static char *http_request_get_header(struct http_request *request,
                                     char *name) 
{
    char   *lowercase_name;
    size_t value_length;
    int    result;
    void  *value;

    lowercase_name = convert_string_to_lowercase(name, strlen(name));

    if (lowercase_name == NULL) {
        return NULL;
    }

    result = flb_hash_table_get(request->headers,
                                lowercase_name, 
                                strlen(lowercase_name),
                                &value, &value_length);

    flb_free(lowercase_name);

    if (result == -1) {
        return NULL;
    }

    return (char *) value;
}

static int http_request_set_header(struct http_request *request,
                                   char *name, size_t name_length,
                                   char *value, size_t value_length) 
{
    char  *lowercase_name;
    int    result;

    lowercase_name = convert_string_to_lowercase(name, name_length);

    if (lowercase_name == NULL) {
        return -1;
    }

    result = flb_hash_table_add(request->headers, 
                                (const char *) lowercase_name, 
                                name_length,
                                (void *) value, 
                                value_length);

    flb_free(lowercase_name);

    if (result == -1) {
        return -1;
    }

    return 0;
}

static void http_request_destroy(struct http_request *request) 
{
    if (request->path != NULL) {
         cfl_sds_destroy(request->path);
    }

    if (request->host != NULL) {
         cfl_sds_destroy(request->host);
    }

    if (request->query_string != NULL) {
         cfl_sds_destroy(request->query_string);
    }

    if (request->body != NULL) {
         cfl_sds_destroy(request->body);
    }

    if (request->headers != NULL) {
         flb_hash_table_destroy(request->headers);
    }

    if (!cfl_list_entry_is_orphan(&request->_head)) {
        cfl_list_del(&request->_head);
    }

    memset(request, 0, sizeof(struct http_request));
}

static int http_request_init(struct http_request *request) {
    http_request_destroy(request);

    cfl_list_entry_init(&request->_head);

    request->headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (request->headers == NULL) {
        return -1;
    }

    return 0;
}

int http_stream_init(struct http_stream *stream,
                     struct http_session *session, 
                     int32_t stream_id)
{
    int result;

    stream->id = stream_id;
    stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;

    result = http_request_init(&stream->request);

    if (result != 0) {
        return -1;
    }

    result = http_response_init(&stream->response);

    if (result != 0) {
        return -2;
    }

    stream->request.stream  = (void *) stream;
    stream->request.session = session;

    stream->response.stream  = (void *) stream;
    stream->response.session = session;

    return 0;
}

void http_stream_destroy(struct http_stream *stream)
{
    if (stream != NULL) {
        if (!cfl_list_entry_is_orphan(&stream->_head)) {
            cfl_list_del(&stream->_head);
        }

        flb_free(stream);
    }
}

struct http_stream *http_stream_create(struct http_session *session, 
                                       int32_t stream_id) 
{
    struct http_stream *stream;
    int                 result;

    stream = flb_calloc(1, sizeof(struct http_stream));

    if (stream == NULL) {
        return NULL;
    }

    stream->releasable = FLB_TRUE;

    result = http_stream_init(stream, session, stream_id);

    if (result != 0) {
        http_stream_destroy(stream);
    }

    return stream;
}

static ssize_t http2_send_callback(nghttp2_session *inner_session, 
                                   const uint8_t *data,
                                   size_t length, 
                                   int flags, 
                                   void *user_data)
{
    cfl_sds_t             resized_buffer;
    struct http2_session *session;

    session = (struct http2_session *) user_data;

    resized_buffer = cfl_sds_cat(session->parent->outgoing_data, 
                                 (const char *) data, 
                                 length);

    if (resized_buffer == NULL) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    session->parent->outgoing_data = resized_buffer;

    return length;
}

static int http2_frame_recv_callback(nghttp2_session *inner_session,
                                     const nghttp2_frame *frame, 
                                     void *user_data)
{
    struct http_stream *stream;

    stream = nghttp2_session_get_stream_user_data(inner_session, 
                                                  frame->hd.stream_id);

    if (stream == NULL) {
        return 0;
    }

    switch (frame->hd.type) {
        case NGHTTP2_CONTINUATION:
        case NGHTTP2_HEADERS:
            if ((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) != 0) {
                if (stream->request.content_length > 0) {
                    stream->status = HTTP_STREAM_STATUS_RECEIVING_DATA;
                }
                else {
                    stream->status = HTTP_STREAM_STATUS_READY;

                    if (!cfl_list_entry_is_orphan(&stream->request._head)) {
                        cfl_list_del(&stream->request._head);
                    }

                    cfl_list_add(&stream->request._head, 
                                 &stream->request.session->request_queue);
                }
            }
            else {
                stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;                
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
    struct http_stream *stream;

    stream = nghttp2_session_get_stream_user_data(session, stream_id);

    if (stream == NULL) {
        return 0;
    }

    stream->status = HTTP_STREAM_STATUS_CLOSED;

    return 0;
}

static int http2_begin_headers_callback(nghttp2_session *inner_session,
                                        const nghttp2_frame *frame,
                                        void *user_data) {
    struct http2_session *session;
    struct http_stream   *stream;

    session = (struct http2_session *) user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    stream = http_stream_create(session->parent, frame->hd.stream_id);

    if (stream == NULL) {
        return -1;
    }

    cfl_list_add(&stream->_head, &session->streams);

    nghttp2_session_set_stream_user_data(inner_session,
                                         frame->hd.stream_id, 
                                         stream);

    return 0;
}


 static int http2_data_chunk_recv_callback(nghttp2_session *inner_session, 
                                           uint8_t flags, 
                                           int32_t stream_id, 
                                           const uint8_t *data, 
                                           size_t len, 
                                           void *user_data)
{
    cfl_sds_t            resized_buffer;
    struct http_stream  *stream;

    stream = nghttp2_session_get_stream_user_data(inner_session, stream_id);

    if (stream == NULL) {
        return 0;
    }

    if (stream->status != HTTP_STREAM_STATUS_RECEIVING_DATA) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        return -1;
    }

    if (stream->request.body == NULL) {
        stream->request.body = cfl_sds_create_size(len);

        if (stream->request.body == NULL) {
            stream->status = HTTP_STREAM_STATUS_ERROR;

            return -1;
        }

        memcpy(stream->request.body, data, len);

        cfl_sds_set_len(stream->request.body, len);
    }
    else {
        resized_buffer = cfl_sds_cat(stream->request.body, 
                                     (const char *) data, 
                                     len);

        if (resized_buffer == NULL) {
            stream->status = HTTP_STREAM_STATUS_ERROR;

            return -1;
        }

        stream->request.body = resized_buffer;
    }

    if (stream->status == HTTP_STREAM_STATUS_RECEIVING_DATA) {
        if (stream->request.content_length == cfl_sds_len(stream->request.body)) {
            stream->status = HTTP_STREAM_STATUS_READY;

            if (!cfl_list_entry_is_orphan(&stream->request._head)) {
                cfl_list_del(&stream->request._head);
            }

            cfl_list_add(&stream->request._head, 
                         &stream->request.session->request_queue);
        }
    }

    return 0;
}


static int http2_header_callback(nghttp2_session *inner_session,
                                 const nghttp2_frame *frame, 
                                 const uint8_t *name,
                                 size_t name_length, 
                                 const uint8_t *value,
                                 size_t value_length, 
                                 uint8_t flags, 
                                 void *user_data) 
{
    char                 temporary_buffer[16];
    char                *lowercase_name;
    struct http_stream  *stream;
    int                  result;

    stream = nghttp2_session_get_stream_user_data(inner_session, 
                                                  frame->hd.stream_id);

    if (stream == NULL) {
        return 0;
    }

    if (http2_strncasecmp(name, name_length, ":method", 0) == 0) {
        strncpy(temporary_buffer, 
                (const char *) value, 
                http2_lower_value(sizeof(temporary_buffer), value_length + 1));

        temporary_buffer[sizeof(temporary_buffer) - 1] = '\0';

        if (strcasecmp(temporary_buffer, "GET") == 0) {
            stream->request.method = MK_METHOD_GET;
        }
        else if (strcasecmp(temporary_buffer, "POST") == 0) {
            stream->request.method = MK_METHOD_POST;
        }
        else if (strcasecmp(temporary_buffer, "HEAD") == 0) {
            stream->request.method = MK_METHOD_HEAD;
        }
        else if (strcasecmp(temporary_buffer, "PUT") == 0) {
            stream->request.method = MK_METHOD_PUT;
        }
        else if (strcasecmp(temporary_buffer, "DELETE") == 0) {
            stream->request.method = MK_METHOD_DELETE;
        }
        else if (strcasecmp(temporary_buffer, "OPTIONS") == 0) {
            stream->request.method = MK_METHOD_OPTIONS;
        }
        else {    
            stream->request.method = MK_METHOD_UNKNOWN;
        }
    }
    else if (http2_strncasecmp(name, name_length, ":path", 0) == 0) {
        stream->request.path = cfl_sds_create_len((const char *) value, value_length);

        if (stream->request.path == NULL) {
            return -1;
        }
    }
    else if (http2_strncasecmp(name, name_length, ":authority", 0) == 0) {

        stream->request.host = cfl_sds_create_len((const char *) value, value_length);
    
        if (stream->request.host == NULL) {
            return -1;
        }

        result = flb_hash_table_add(stream->request.headers, 
                                    "host", 4, 
                                    (void *) value, value_length);

        if (result < 0) {
            return -1;
        }
    }
    else if (http2_strncasecmp(name, name_length, "content-length", 0) == 0) {
        strncpy(temporary_buffer, 
                (const char *) value, 
                http2_lower_value(sizeof(temporary_buffer), value_length + 1));

        temporary_buffer[sizeof(temporary_buffer) - 1] = '\0';

        stream->request.content_length = strtoull(temporary_buffer, NULL, 10);
    }

    lowercase_name = convert_string_to_lowercase(name, name_length);

    if (lowercase_name == NULL) {
        return -1;
    }

    result = flb_hash_table_add(stream->request.headers, 
                                (const char *) lowercase_name, 
                                strlen(lowercase_name), 
                                (void *) value, 
                                value_length);

    flb_free(lowercase_name);

    return 0;
}

static void dummy_mk_http_session_init(struct mk_http_session *session, 
                                       struct mk_server *server)
{
    session->_sched_init = MK_TRUE;
    session->pipelined   = MK_FALSE;
    session->counter_connections = 0;
    session->close_now = MK_FALSE;
    session->status = MK_REQUEST_STATUS_INCOMPLETE;
    session->server = server;
    session->socket = -1;

    /* creation time in unix time */
    session->init_time = time(NULL);

    session->channel = mk_channel_new(MK_CHANNEL_SOCKET, -1);
    session->channel->io = session->server->network;

    /* Init session request list */
    mk_list_init(&session->request_list);

    /* Initialize the parser */
    mk_http_parser_init(&session->parser);
}

static void dummy_mk_http_request_init(struct mk_http_session *session,
                                       struct mk_http_request *request)
{
    memset(request, 0, sizeof(struct mk_http_request));

    mk_http_request_init(session, request, session->server);

    request->in_headers.type        = MK_STREAM_IOV;
    request->in_headers.dynamic     = MK_FALSE;
    request->in_headers.cb_consumed = NULL;
    request->in_headers.cb_finished = NULL;
    request->in_headers.stream      = &request->stream;

    mk_list_add(&request->in_headers._head, &request->stream.inputs);

    request->session = session;
}

static int http1_session_init(struct http1_session *session, struct http_session *parent)
{
    int result;

    dummy_mk_http_session_init(&session->inner_session, &session->inner_server);

    dummy_mk_http_request_init(&session->inner_session, &session->inner_request);

    mk_http_parser_init(&session->inner_parser);

    result = http_stream_init(&session->stream, parent, 0);

    if (result != 0) {
        return -1;
    }

    session->parent = parent;

    return 0;
}

static int http2_session_init(struct http2_session *session, struct http_session *parent)
{
    nghttp2_settings_entry     session_settings[1];
    nghttp2_session_callbacks *callbacks;
    int                        result;

    result = nghttp2_session_callbacks_new(&callbacks);

    if (result != 0) {
        return -1;
    }

    nghttp2_session_callbacks_set_send_callback(callbacks, http2_send_callback);

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

    cfl_list_init(&session->streams);

    session->parent = parent;

    session_settings[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    session_settings[0].value = 1;

    result = nghttp2_submit_settings(session->inner_session, 
                                     NGHTTP2_FLAG_NONE, 
                                     session_settings,
                                     1);

    if (result != 0) {
        return -3;
    }

    result = nghttp2_session_send(session->inner_session);

    if (result != 0) {
        return -4;
    }

    return 0;
}

static int http_session_init(struct http_session *session, int version) {
    int result;

    memset(session, 0, sizeof(struct http_session));

    cfl_list_init(&session->request_queue);

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
        result = http2_session_init(&session->http2, session);

        if (result != 0) {
            return -3;
        }
    }
    else if (session->version == HTTP_PROTOCOL_HTTP1) {
        result = http1_session_init(&session->http1, session);

        if (result != 0) {
            return -4;
        }
    }

    return 0;
}

static void http1_session_destroy(struct http1_session *session)
{
    if (session->inner_session.channel != NULL) {
        mk_channel_release(session->inner_session.channel);

        session->inner_session.channel = NULL;
    }
}

static void http2_session_destroy(struct http2_session *session)
{
    struct cfl_list     *iterator_backup;
    struct cfl_list     *iterator;
    struct http_stream  *stream;

    if (session != NULL) {
        cfl_list_foreach_safe(iterator, 
                              iterator_backup, 
                              &session->streams) {
            stream = cfl_list_entry(iterator, struct http_stream, _head);

            http_stream_destroy(stream);
        }

        nghttp2_session_del(session->inner_session);
    }
}

static void http_session_destroy(struct http_session *session)
{
    if (session != NULL) {
        if (session->incoming_data != NULL) {
            cfl_sds_destroy(session->incoming_data);
        }

        if (session->outgoing_data != NULL) {
            cfl_sds_destroy(session->outgoing_data);
        }

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

static ssize_t http2_data_source_read_callback(nghttp2_session *session, 
                                               int32_t stream_id, 
                                               uint8_t *buf, 
                                               size_t length, 
                                               uint32_t *data_flags, 
                                               nghttp2_data_source *source, 
                                               void *user_data)
{
    size_t               content_length;
    size_t               body_offset;
    struct http_stream  *stream;
    ssize_t              result;

    stream = nghttp2_session_get_stream_user_data(session, 
                                                  stream_id);

    if (stream == NULL) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    body_offset    = stream->response.body_read_offset;
    content_length = cfl_sds_len(stream->response.body) - body_offset;

    if (content_length > length) {
        memcpy(buf, 
               &stream->response.body[body_offset], length);
        
        result = length;

        stream->response.body_read_offset += length;
    }
    else if (content_length > 0) {
        memcpy(buf, stream->response.body, content_length);

        result = content_length;

        stream->response.body_read_offset += length;

        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    else {
        result = NGHTTP2_ERR_PAUSE;
    }

    return result;
}

static void http_response_destroy(struct http_response *response) {
    if (response->message != NULL) {
         cfl_sds_destroy(response->message);
    }

    if (response->body != NULL) {
         cfl_sds_destroy(response->body);
    }

    if (response->headers != NULL) {
         flb_hash_table_destroy(response->headers);
    }

    memset(response, 0, sizeof(struct http_response));
}

static int http_response_init(struct http_response *response) {
    http_response_destroy(response);

    response->headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (response->headers == NULL) {
        return -1;
    }

    return 0;
}

static struct http_response *http2_response_begin(
        struct http2_session *session, 
        struct http_stream *stream) {

    int result;

    result = http_response_init(&stream->response);

    if (result != 0) {
        return NULL;
    }

    stream->response.stream = (void *) stream;
    stream->response.session = session->parent;

    return &stream->response;
}

static int http2_response_set_header(struct http_response *response, 
                                     char *name, size_t name_length,
                                     char *value, size_t value_length)
{
    int result;

    result = flb_hash_table_add(response->headers, 
                                (const char *) name, (int) name_length,
                                (void *) value, (ssize_t) value_length);

    if (result < 0) {
        return -1;
    }

    return 0;
}

static int http2_response_set_status(struct http_response *response, 
                                     int status)
{
    return 0;
}

static int http2_response_set_body(struct http_response *response, 
                                   unsigned char *body, size_t body_length)
{
    return 0;
}

static int http2_response_commit(struct http_response *response)
{
    char                         status_as_text[16];
    struct mk_list              *header_iterator;
    nghttp2_data_provider        data_provider;
    size_t                       header_count;
    size_t                       header_index;
    struct flb_hash_table_entry *header_entry;
    nghttp2_nv                  *headers;
    struct http2_session        *session;
    struct http_stream          *stream;
    int                          result;

    session = &response->session->http2;

    if (session == NULL) {
        return -1;
    }

    stream  = (struct http_stream *) response->stream;

    if (stream == NULL) {
        return -2;
    }

    header_count = response->headers->total_count + 1;

    headers = flb_calloc(header_count, sizeof(nghttp2_nv));

    if (headers == NULL) {
        return -3;
    }

    snprintf(status_as_text, 
             sizeof(status_as_text) - 1, 
             "%d", 
             response->status);

    headers[0].name = (uint8_t *) ":status";
    headers[0].namelen = strlen(":status");
    headers[0].value = (uint8_t *) status_as_text;
    headers[0].valuelen = strlen(status_as_text);

    header_index = 1;

    mk_list_foreach(header_iterator, &response->headers->entries) {
        header_entry = mk_list_entry(header_iterator, 
                                     struct flb_hash_table_entry, 
                                     _head_parent);

        if (header_entry == NULL) {
            return -4;
        }

        headers[header_index].name = (uint8_t *) header_entry->key;
        headers[header_index].namelen = header_entry->key_len;
        headers[header_index].value = (uint8_t *) header_entry->val;
        headers[header_index].valuelen = header_entry->val_size;

        header_index++;
    }

    data_provider.source.fd = 0;
    data_provider.read_callback = http2_data_source_read_callback;

    stream->status = HTTP_STREAM_STATUS_PROCESSING;

    result = nghttp2_submit_response(session->inner_session, 
                                     stream->id, 
                                     headers, 
                                     header_count, 
                                     &data_provider);

    flb_free(headers);

    if (result != 0) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        return -5;
    }

    result = nghttp2_session_send(session->inner_session);

    if (result != 0) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        return -6;
    }

    stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;

    http_response_destroy(&stream->response);

    return 0;
}

static struct http_response *http1_response_begin(
        struct http1_session *session, 
        struct http_stream *stream) {

    int result;

    result = http_response_init(&stream->response);

    if (result != 0) {
        return NULL;
    }

    stream->response.stream = (void *) stream;
    stream->response.session = session->parent;

    return &stream->response;
}

static int http1_response_set_header(struct http_response *response, 
                                     char *name, size_t name_length,
                                     char *value, size_t value_length)
{
    int result;

    result = flb_hash_table_add(response->headers, 
                                (const char *) name, (int) name_length,
                                (void *) value, (ssize_t) value_length);

    if (result < 0) {
        return -1;
    }

    return 0;
}

static int http1_response_set_status(struct http_response *response, 
                                     int status)
{
    return 0;
}

static int http1_response_set_body(struct http_response *response, 
                                   unsigned char *body, size_t body_length)
{
    return 0;
}

static int http1_response_commit(struct http_response *response)
{
    struct mk_list              *header_iterator;
    cfl_sds_t                    response_buffer;
    struct flb_hash_table_entry *header_entry;
    cfl_sds_t                    sds_result;
    struct http1_session        *session;
    struct http1_stream         *stream;

    session = &response->session->http1;

    if (session == NULL) {
        return -1;
    }

    stream  = (struct http_stream *) response->stream;

    if (stream == NULL) {
        return -2;
    }

    response_buffer = cfl_sds_create_size(128);

    if (response_buffer == NULL) {
        return -3;
    }

    if (response->message != NULL) {
        sds_result = cfl_sds_printf(&response_buffer, "HTTP/1.1 %d %s\r\n", response->status, response->message);
    }
    else {
        sds_result = cfl_sds_printf(&response_buffer, "HTTP/1.1 %d\r\n", response->status);
    }

    if (sds_result == NULL) {
        cfl_sds_destroy(response_buffer);

        return -4;
    }

    mk_list_foreach(header_iterator, &response->headers->entries) {
        header_entry = mk_list_entry(header_iterator, 
                                     struct flb_hash_table_entry, 
                                     _head_parent);

        if (header_entry == NULL) {
            cfl_sds_destroy(response_buffer);

            return -5;
        }

        sds_result = cfl_sds_printf(&response_buffer, 
                                    "%.*s: %.*s\r\n", 
                                    (int) header_entry->key_len, 
                                    (const char *) header_entry->key, 
                                    (int) header_entry->val_size, 
                                    (const char *) header_entry->val);

        if (sds_result == NULL) {
            cfl_sds_destroy(response_buffer);

            return -6;
        }
    }

    sds_result = cfl_sds_cat(response_buffer, "\r\n", 2);

    if (sds_result == NULL) {
        cfl_sds_destroy(response_buffer);

        return -7;
    }

    if (response->body != NULL) {
        sds_result = cfl_sds_cat(response_buffer, 
                                 response->body,
                                 cfl_sds_len(response->body));

        if (sds_result == NULL) {
            cfl_sds_destroy(response_buffer);

            return -8;
        }
     
        response_buffer = sds_result;
    }

    sds_result = cfl_sds_cat(session->parent->outgoing_data, 
                             response_buffer, 
                             cfl_sds_len(response_buffer));

    if (sds_result == NULL) {
        return -9;
    }

    session->parent->outgoing_data = sds_result;

    return 0;
}

static struct http_response *http_response_begin(
        struct http_session *session, 
        void *stream) {

    if (session->version == HTTP_PROTOCOL_HTTP2) {
        return http2_response_begin(&session->http2, stream);
    }
    else {
        return http1_response_begin(&session->http1, stream);
    }
}

static int http_response_set_header(struct http_response *response, 
                                    char *name, size_t name_length,
                                    char *value, size_t value_length)
{

    if (response->session->version == HTTP_PROTOCOL_HTTP2) {
        return http2_response_set_header(response, 
                                         name, name_length, 
                                         value, value_length);
    }
    else {
        return http1_response_set_header(response, 
                                         name, name_length, 
                                         value, value_length);
    }
}

static int http_response_set_status(struct http_response *response, 
                                    int status)
{
    response->status = status;

    if (response->session->version == HTTP_PROTOCOL_HTTP2) {
        return http2_response_set_status(response, status);
    }

    return http1_response_set_status(response, status);
}

static int http_response_set_message(struct http_response *response, 
                                     char *message)
{
    if (response->message != NULL) {
        cfl_sds_destroy(response->message);

        response->message = NULL;
    }

    response->message = cfl_sds_create((const char *) message);
    
    if (response->message == NULL) {
        return -1;
    }

    return 0;
}

static int http_response_set_body(struct http_response *response, 
                                  unsigned char *body, size_t body_length)
{
    response->body = cfl_sds_create_len((const char *) body, body_length);
    
    if (response->session->version == HTTP_PROTOCOL_HTTP2) {
        return http2_response_set_body(response, body, body_length);
    }

    return http1_response_set_body(response, body, body_length);
}

static int http_response_commit(struct http_response *response) {

    if (response->session->version == HTTP_PROTOCOL_HTTP2) {
        return http2_response_commit(response);
    }

    return http1_response_commit(response);
}

int http2_session_ingest(struct http2_session *session, 
                         unsigned char *buffer, 
                         size_t length)
{
    ssize_t result;

    result = nghttp2_session_mem_recv(session->inner_session, buffer, length);

    if (result < 0) {
        return HTTP_SERVER_PROVIDER_ERROR;
    }

    return HTTP_SERVER_SUCCESS;   
}

static int http1_evict_request(struct http1_session *session)
{
    uintptr_t session_buffer_upper_bound;
    uintptr_t session_buffer_lower_bound;
    size_t    session_buffer_length;
    cfl_sds_t session_buffer;
    size_t    content_length;
    size_t    request_length;
    uintptr_t request_end;

    request_end = 0;
    content_length = 0;
    session_buffer = session->parent->incoming_data;

    if (session_buffer == NULL) {
        return -1;
    }

    session_buffer_length = cfl_sds_len(session_buffer);

    if (session->inner_request.data.data != NULL) {
        content_length = session->inner_request.data.len;

        request_end  = (uintptr_t) session->inner_request.data.data;
        request_end += content_length;
    }
    else {
        request_end = (uintptr_t) strstr(session_buffer, 
                                         "\r\n\r\n");

        if(request_end != 0) {
            request_end += 4;
        }
    }

    if (request_end != 0) {
        session_buffer_lower_bound = (uintptr_t) session_buffer;
        session_buffer_upper_bound = (uintptr_t) &session_buffer[session_buffer_length];

        if (request_end < session_buffer_lower_bound ||
            request_end > session_buffer_upper_bound) {
            return -1;
        }

        request_length = (size_t) (request_end - session_buffer_lower_bound);

        if (request_length == session_buffer_length) {
            session_buffer_length = 0;
        }
        else {
            session_buffer_length -= request_length;

            memmove(session_buffer, 
                    &session_buffer[request_length],
                    session_buffer_length);

            session_buffer[session_buffer_length] = '\0';
        }

        cfl_sds_set_len(session_buffer, session_buffer_length);
    }

    return 0;
}

static int http1_session_process_request(struct http1_session *session)
{
    struct mk_list         *iterator;
    struct mk_http_header  *header;
    int                     result;

    if (session->inner_request.uri_processed.data != NULL) {
        session->stream.request.path = \
            cfl_sds_create_len(session->inner_request.uri_processed.data, 
                               session->inner_request.uri_processed.len);
    }
    else {
        session->stream.request.path = \
            cfl_sds_create_len(session->inner_request.uri.data, 
                               session->inner_request.uri.len);
    }

    if (session->stream.request.path == NULL) {    
        return -1;
    }

    session->stream.request.method = session->inner_request.method;

    session->stream.request.content_length = session->inner_request.content_length;

    mk_list_foreach(iterator, 
                    &session->inner_parser.header_list) {
        header = mk_list_entry(iterator, struct mk_http_header, _head);

        if (header->key.data != NULL && header->key.len > 0 &&
            header->val.data != NULL && header->val.len > 0) {

            if (http2_strncasecmp(header->key.data, 
                                  header->key.len, 
                                  "host", 0) == 0) {
                session->stream.request.host = \
                    cfl_sds_create_len((const char *) header->val.data, 
                                       header->val.len);
            
                if (session->stream.request.host == NULL) {
                    return -1;
                }
            }

            result = http_request_set_header(&session->stream.request, 
                                             header->key.data, 
                                             header->key.len, 
                                             (void *) header->val.data, 
                                             header->val.len);

            if (result != 0) {
                return -1;
            }
        }
    }

    if (session->stream.request.host == NULL) {
        session->stream.request.host = cfl_sds_create("");

        if (session->stream.request.host == NULL) {
            return -1;
        }
    }

    if (session->inner_request.data.data != NULL) {    
        printf("CREATING BODY OF : %zu\n", session->inner_request.data.len);

        session->stream.request.body = \
            cfl_sds_create_len(session->inner_request.data.data, 
                               session->inner_request.data.len);

        printf("CREATED BODY OF : %zu\n", cfl_sds_len(session->stream.request.body));

        if (session->stream.request.body == NULL) {
            session->stream.status = HTTP_STREAM_STATUS_ERROR;

            return -1;
        }
    }

    session->stream.status = HTTP_STREAM_STATUS_READY;

    if (!cfl_list_entry_is_orphan(&session->stream.request._head)) {
        cfl_list_del(&session->stream.request._head);
    }

    cfl_list_add(&session->stream.request._head, 
                 &session->parent->request_queue);

    return 0;
}

int http1_session_ingest(struct http1_session *session, 
                         unsigned char *buffer, 
                         size_t length)
{
    int result;

    result = mk_http_parser(&session->inner_request, 
                            &session->inner_parser, 
                            session->parent->incoming_data, 
                            cfl_sds_len(session->parent->incoming_data), 
                            &session->inner_server);

    if (result == MK_HTTP_PARSER_OK) {
        result = http1_session_process_request(session);

        if (result != 0) {
            session->stream.status = HTTP_STREAM_STATUS_ERROR;

            return HTTP_SERVER_PROVIDER_ERROR;
        }

        http1_evict_request(session);
    }

    return HTTP_SERVER_SUCCESS;   
}

int http_session_ingest(struct http_session *session, 
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
            result = http1_session_init(&session->http1, session);

            if (result != 0) {
                return -1;
            }
        }
        else if (session->version == HTTP_PROTOCOL_HTTP2) {
            result = http2_session_init(&session->http2, session);

            if (result != 0) {
                return -1;
            }
        }
    }

    if (session->version == HTTP_PROTOCOL_HTTP1) {
        return http1_session_ingest(&session->http1, 
                                    buffer, 
                                    length);
    }
    else if (session->version == HTTP_PROTOCOL_HTTP2) {
        return http2_session_ingest(&session->http2, 
                                    buffer, 
                                    length);
    }

    return -1;
}

static int http2_conn_ingest(struct http_conn *connection)
{
    unsigned char input_buffer[1024];
    ssize_t result;

    result = flb_io_net_read(connection->connection,
                             (void *) &input_buffer,
                             sizeof(input_buffer));

    if (result <= 0) {
        return -1;
    }

    result = (ssize_t) http_session_ingest(&connection->session_, 
                                           input_buffer, 
                                           result);

    if (result < 0) {
        return -1;
    }

    return 0;
}

static int http2_conn_event(void *data)
{
    struct flb_connection *connection;
    struct http_conn *conn;
    struct mk_event *event;
    struct flb_http *ctx;
    int result;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    event = &connection->event;

    if (event->mask & MK_EVENT_READ) {
        result = http2_conn_ingest(conn);

        if (result == -1) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);

            http2_conn_del(conn);

            return -1;
        }
    }

    {
        struct cfl_list     *backup_iterator;
        struct cfl_list     *iterator;
        struct http_request *request;
        struct http_stream  *stream;

/* REQUEST SERVICING */
        cfl_list_foreach_safe(iterator, 
                              backup_iterator, 
                              &conn->session_.request_queue) {
            request = cfl_list_entry(iterator, struct http_request, _head);
            stream = (struct http_stream *) request->stream;

            if (request->method == MK_METHOD_POST) {
                {
                    int zz;

                    printf("BODY LENGTH : %zu\n\n", cfl_sds_len(stream->request.body));

                    for (zz = 0 ; zz < cfl_sds_len(request->body) ; zz++) {
                        printf("%c", request->body[zz]);
                    }

                    printf("\n\n");
                }
            }

            {
                char *sample;

                sample = http_request_get_header(request, "user-agent");

                if (sample != NULL) {
                    printf("HEADER VALUE = %s\n", sample);
                }
            }

            {
                struct http_response *response;

                response = http_response_begin(&conn->session_, stream);
                
                http_response_set_header(response, "test", 4, "value", 5);
                http_response_set_header(response, "content-length", 14, "5", 1);
                http_response_set_status(response, 200);
                http_response_set_message(response, "TEST MESSAGE!");
                http_response_set_body(response, "TEST!", 5);
                http_response_commit(response);
            }

            http_request_destroy(&stream->request);
        }
    }

/* IO */ 
    result = http2_conn_flush_session(&conn->session_);

    if (result == -1) {
        http2_conn_del(conn);

        return -1;
    }

    return 0;
}

int http2_conn_flush_session(struct http_session *session) 
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
            return -1;
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

struct http_conn *http2_conn_add(struct flb_connection *connection,
                                struct flb_http *ctx)
{
    struct http_conn *conn;
    int               ret;

    conn = flb_calloc(1, sizeof(struct http_conn));

    if (conn == NULL) {
        flb_errno();

        return NULL;
    }

    cfl_list_init(&conn->session_.http2.streams);

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

        http2_conn_del(conn);

        return NULL;
    }

    ret = http_session_init(&conn->session_, 0);

    if (ret != 0) {
        http2_conn_del(conn);

        return NULL;
    }

    conn->session_.connection = connection;

    /* Link connection node to parent context list */
    mk_list_add(&conn->_head, &ctx->connections);

    ret = http2_conn_flush_session(&conn->session_);

    if (ret == -1) {
        http2_conn_del(conn);

        return NULL;
    }

    return conn;
}

int http2_conn_del(struct http_conn *conn)
{
    /* The downstream unregisters the file descriptor from the event-loop
     * so there's nothing to be done by the plugin
     */

    flb_downstream_conn_release(conn->connection);

    if (!cfl_list_entry_is_orphan(&conn->_head)) {
        mk_list_del(&conn->_head);
    }

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

















static int http2_strncasecmp(const uint8_t *first_buffer, 
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


// static struct mk_http_header *get_legacy_header(struct mk_http_parser *parser,
//                                                 int header_id)
// {
//     struct mk_http_header *header;

//     header = NULL;

//     if (parser != NULL) {
//         if (header_id >= MK_HEADER_ACCEPT && 
//             header_id <= MK_HEADER_SIZEOF) {

//             header = &parser->headers[header_id];
//         }
//         else {
//             if (parser->headers_extra_count > MK_HEADER_EXTRA_SIZE) {
//                 header = &parser->headers_extra[header_id - MK_HEADER_SIZEOF];
//             }
//         }
//     }

//     return header;
// }
