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

/* PRIVATE */
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

static int http2_frame_recv_callback(nghttp2_session *inner_session,
                                     const nghttp2_frame *frame, 
                                     void *user_data);

static int http2_stream_close_callback(nghttp2_session *session, 
                                       int32_t stream_id,
                                       uint32_t error_code, 
                                       void *user_data);

static int http2_begin_headers_callback(nghttp2_session *inner_session,
                                        const nghttp2_frame *frame,
                                        void *user_data);

static int http2_data_chunk_recv_callback(nghttp2_session *inner_session, 
                                          uint8_t flags, 
                                          int32_t stream_id, 
                                          const uint8_t *data, 
                                          size_t len, 
                                          void *user_data);

static ssize_t http2_data_source_read_callback(nghttp2_session *session, 
                                               int32_t stream_id, 
                                               uint8_t *buf, 
                                               size_t length, 
                                               uint32_t *data_flags, 
                                               nghttp2_data_source *source, 
                                               void *user_data);

static inline size_t http2_lower_value(size_t left_value, size_t right_value) 
{
    if (left_value < right_value) {
        return left_value;
    }

    return right_value;
}

/* RESPONSE */

struct flb_http_response *flb_http2_response_begin(
                                struct flb_http2_server_session *session, 
                                struct flb_http_stream *stream)
{

    int result;

    result = flb_http_response_init(&stream->response);

    if (result != 0) {
        return NULL;
    }

    stream->response.stream = stream;

    return &stream->response;
}

int flb_http2_response_set_header(struct flb_http_response *response, 
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

int flb_http2_response_set_status(struct flb_http_response *response, 
                              int status)
{
    return 0;
}

int flb_http2_response_set_body(struct flb_http_response *response, 
                            unsigned char *body, size_t body_length)
{
    return 0;
}

int flb_http2_response_commit(struct flb_http_response *response)
{
    size_t                           trailer_header_count;
    char                             status_as_text[16];
    struct mk_list                  *header_iterator;
    nghttp2_nv                      *trailer_headers;
    struct flb_http_server_session  *parent_session;
    nghttp2_data_provider            data_provider;
    size_t                           header_count;
    size_t                           header_index;
    struct flb_hash_table_entry     *header_entry;
    nghttp2_nv                      *headers;
    struct flb_http2_server_session *session;
    struct flb_http_stream          *stream;
    int                              result;

    parent_session = (struct flb_http_server_session *) response->stream->parent;

    if (parent_session == NULL) {
        return -1;
    }

    session = &parent_session->http2;

    if (session == NULL) {
        return -1;
    }

    stream  = (struct flb_http_stream *) response->stream;

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
            flb_free(headers);

            return -4;
        }

        headers[header_index].name = (uint8_t *) header_entry->key;
        headers[header_index].namelen = header_entry->key_len;
        headers[header_index].value = (uint8_t *) header_entry->val;
        headers[header_index].valuelen = header_entry->val_size;

        if (headers[header_index].value[0] == '\0') {
            headers[header_index].valuelen = 0;
        }

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

    if (result != 0) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        flb_free(headers);

        return -5;
    }

    result = nghttp2_session_send(session->inner_session);

    if (mk_list_is_empty(&response->trailer_headers->entries) != 0) {
        trailer_header_count = response->trailer_headers->total_count;
        
        trailer_headers = flb_calloc(trailer_header_count, sizeof(nghttp2_nv));

        if (trailer_headers == NULL) {
            flb_free(headers);

            return -6;
        }

        header_index = 0;

        mk_list_foreach(header_iterator, &response->trailer_headers->entries) {
            header_entry = mk_list_entry(header_iterator, 
                                         struct flb_hash_table_entry, 
                                         _head_parent);

            if (header_entry == NULL) {
                flb_free(trailer_headers);
                flb_free(headers);

                return -7;
            }

            trailer_headers[header_index].name = (uint8_t *) header_entry->key;
            trailer_headers[header_index].namelen = header_entry->key_len;
            trailer_headers[header_index].value = (uint8_t *) header_entry->val;
            trailer_headers[header_index].valuelen = header_entry->val_size;

            if (trailer_headers[header_index].value[0] == '\0') {
                trailer_headers[header_index].valuelen = 0;
            }

            header_index++;
        }

        result = nghttp2_submit_trailer(session->inner_session, 
                                        stream->id,
                                        trailer_headers,
                                        trailer_header_count);
    }
    else {
        trailer_headers = NULL;
    }

    result = nghttp2_session_send(session->inner_session);

    if (trailer_headers != NULL) {
        flb_free(trailer_headers);
    }

    flb_free(headers);

    if (result != 0) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        return -8;
    }

    stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;

    return 0;
}

/* SESSION */

int flb_http2_server_session_init(struct flb_http2_server_session *session, 
                       struct flb_http_server_session *parent)
{
    nghttp2_settings_entry     session_settings[1];
    nghttp2_session_callbacks *callbacks;
    int                        result;

    session->parent = parent;
    session->initialized = FLB_TRUE;
    session->inner_session = NULL;

    cfl_list_init(&session->streams);

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

void flb_http2_server_session_destroy(struct flb_http2_server_session *session)
{
    struct cfl_list     *iterator_backup;
    struct cfl_list     *iterator;
    struct flb_http_stream  *stream;

    if (session != NULL) {
        if (session->initialized) {
            cfl_list_foreach_safe(iterator, 
                                iterator_backup, 
                                &session->streams) {
                stream = cfl_list_entry(iterator, struct flb_http_stream, _head);

                flb_http_stream_destroy(stream);
            }

            nghttp2_session_del(session->inner_session);

            session->initialized = FLB_FALSE;
        }
    }
}

int flb_http2_server_session_ingest(struct flb_http2_server_session *session, 
                         unsigned char *buffer, 
                         size_t length)
{
    ssize_t result;

    result = nghttp2_session_mem_recv(session->inner_session, buffer, length);

    if (result < 0) {
        return HTTP_SERVER_PROVIDER_ERROR;
    }
    
    result = nghttp2_session_send(session->inner_session);

    if (result < 0) {
        return HTTP_SERVER_PROVIDER_ERROR;
    }

    return HTTP_SERVER_SUCCESS;   
}


/* PRIVATE */

static ssize_t http2_send_callback(nghttp2_session *inner_session, 
                                   const uint8_t *data,
                                   size_t length, 
                                   int flags, 
                                   void *user_data)
{
    cfl_sds_t                        resized_buffer;
    struct flb_http2_server_session *session;

    session = (struct flb_http2_server_session *) user_data;

    resized_buffer = cfl_sds_cat(session->parent->outgoing_data, 
                                 (const char *) data, 
                                 length);

    if (resized_buffer == NULL) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    session->parent->outgoing_data = resized_buffer;

    return length;
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
    char                     temporary_buffer[16];
    struct flb_http_stream  *stream;
    int                      result;

    stream = nghttp2_session_get_stream_user_data(inner_session, 
                                                  frame->hd.stream_id);

    if (stream == NULL) {
        return 0;
    }

    if (flb_http_server_strncasecmp(name, name_length, ":method", 0) == 0) {
        strncpy(temporary_buffer, 
                (const char *) value, 
                http2_lower_value(sizeof(temporary_buffer), value_length + 1));

        temporary_buffer[sizeof(temporary_buffer) - 1] = '\0';

        if (strcasecmp(temporary_buffer, "GET") == 0) {
            stream->request.method = HTTP_METHOD_GET;
        }
        else if (strcasecmp(temporary_buffer, "POST") == 0) {
            stream->request.method = HTTP_METHOD_POST;
        }
        else if (strcasecmp(temporary_buffer, "HEAD") == 0) {
            stream->request.method = HTTP_METHOD_HEAD;
        }
        else if (strcasecmp(temporary_buffer, "PUT") == 0) {
            stream->request.method = HTTP_METHOD_PUT;
        }
        else if (strcasecmp(temporary_buffer, "DELETE") == 0) {
            stream->request.method = HTTP_METHOD_DELETE;
        }
        else if (strcasecmp(temporary_buffer, "OPTIONS") == 0) {
            stream->request.method = HTTP_METHOD_OPTIONS;
        }
        else {    
            stream->request.method = HTTP_METHOD_UNKNOWN;
        }
    }
    else if (flb_http_server_strncasecmp(name, name_length, ":path", 0) == 0) {
        stream->request.path = cfl_sds_create_len((const char *) value, value_length);

        if (stream->request.path == NULL) {
            return -1;
        }
    }
    else if (flb_http_server_strncasecmp(
                name, name_length, ":authority", 0) == 0) {

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
    else if (flb_http_server_strncasecmp(
                name, name_length, "content-type", 0) == 0) {

        stream->request.content_type = cfl_sds_create_len((const char *) value, value_length);
    
        if (stream->request.content_type == NULL) {
            return -1;
        }
    }
    else if (flb_http_server_strncasecmp(
                name, name_length, "content-length", 0) == 0) {
        strncpy(temporary_buffer, 
                (const char *) value, 
                http2_lower_value(sizeof(temporary_buffer), value_length + 1));

        temporary_buffer[sizeof(temporary_buffer) - 1] = '\0';

        stream->request.content_length = strtoull(temporary_buffer, NULL, 10);
    }

    result = flb_http_request_set_header(&stream->request, 
                                         (char *) name, 
                                         name_length, 
                                         (void *) value, 
                                         value_length);

    if (result != 0) {
        return -1;
    }

    return 0;
}

static int http2_frame_recv_callback(nghttp2_session *inner_session,
                                     const nghttp2_frame *frame, 
                                     void *user_data)
{
    struct flb_http_server_session  *parent_session;
    struct flb_http_stream          *stream;

    stream = nghttp2_session_get_stream_user_data(inner_session, 
                                                  frame->hd.stream_id);

    if (stream == NULL) {
        return 0;
    }

    switch (frame->hd.type) {
        case NGHTTP2_CONTINUATION:
        case NGHTTP2_HEADERS:
            if ((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) != 0) {
                stream->status = HTTP_STREAM_STATUS_RECEIVING_DATA;
            }
            else {
                stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;                
            }

            break;
        default:
            break;
    }

    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
        stream->status = HTTP_STREAM_STATUS_READY;

        if (!cfl_list_entry_is_orphan(&stream->request._head)) {
            cfl_list_del(&stream->request._head);
        }

        parent_session = (struct flb_http_server_session *) stream->parent;

        if (parent_session == NULL) {
            return -1;
        }

        cfl_list_add(&stream->request._head, 
                        &parent_session->request_queue);
    }

    return 0;
}

static int http2_stream_close_callback(nghttp2_session *session, 
                                       int32_t stream_id,
                                       uint32_t error_code, 
                                       void *user_data)
{
    struct flb_http_stream *stream;

    stream = nghttp2_session_get_stream_user_data(session, stream_id);

    if (stream == NULL) {
        return 0;
    }

    stream->status = HTTP_STREAM_STATUS_CLOSED;

    return 0;
}

static int http2_begin_headers_callback(nghttp2_session *inner_session,
                                        const nghttp2_frame *frame,
                                        void *inner_user_data)
{
    void                            *user_data;
    struct flb_http2_server_session *session;
    struct flb_http_stream          *stream;
    
    session = (struct flb_http2_server_session *) inner_user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    if (session->parent != NULL && session->parent->parent != NULL) {
        user_data = session->parent->parent->user_data;
    }
    else {
        user_data = NULL;
    }

    stream = flb_http_stream_create(session->parent, 
                                    frame->hd.stream_id, 
                                    HTTP_STREAM_ROLE_SERVER,
                                    user_data);

    if (stream == NULL) {
        return -1;
    }

    stream->request.protocol_version = HTTP_PROTOCOL_VERSION_20;

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
    struct flb_http_server_session  *parent_session;
    cfl_sds_t                        resized_buffer;
    struct flb_http_stream          *stream;

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

            parent_session = (struct flb_http_server_session *) stream->parent;

            if (parent_session == NULL) {
                return -1;
            }

            cfl_list_add(&stream->request._head, 
                         &parent_session->request_queue);
        }
    }

    return 0;
}

static ssize_t http2_data_source_read_callback(nghttp2_session *session, 
                                               int32_t stream_id, 
                                               uint8_t *buf, 
                                               size_t length, 
                                               uint32_t *data_flags, 
                                               nghttp2_data_source *source, 
                                               void *user_data)
{
    size_t                   content_length;
    size_t                   body_offset;
    struct flb_http_stream  *stream;
    ssize_t                  result;

    stream = nghttp2_session_get_stream_user_data(session, 
                                                  stream_id);

    if (stream == NULL) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (stream->response.body != NULL) {
        body_offset    = stream->response.body_read_offset;
        content_length = cfl_sds_len(stream->response.body) - body_offset;
    }
    else {
        body_offset = 0;
        content_length = 0;
    }

    if (content_length > length) {
        memcpy(buf, 
               &stream->response.body[body_offset], length);
        
        result = length;

        stream->response.body_read_offset += length;
    }
    else {
        if (content_length > 0) {
            memcpy(buf, stream->response.body, content_length);

            stream->response.body_read_offset += content_length;
        }

        result = content_length;

        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

        if (mk_list_is_empty(&stream->response.trailer_headers->entries) != 0) {
            *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        }
    }

    return result;
}

