/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_http_client_debug.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/tls/flb_tls.h>


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

/* PRIVATE */

static ssize_t http2_send_callback(nghttp2_session *inner_session,
                                   const uint8_t *data,
                                   size_t length,
                                   int flags,
                                   void *user_data)
{
    cfl_sds_t                        resized_buffer;
    struct flb_http2_client_session *session;

    session = (struct flb_http2_client_session *) user_data;

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

    if (flb_http_server_strncasecmp(
                name, name_length, ":status", 0) == 0) {
        strncpy(temporary_buffer,
                (const char *) value,
                http2_lower_value(sizeof(temporary_buffer), value_length + 1));

        temporary_buffer[sizeof(temporary_buffer) - 1] = '\0';

        stream->response.status = strtoull(temporary_buffer, NULL, 10);
    }
    else if (flb_http_server_strncasecmp(
                name, name_length, "content-type", 0) == 0) {

        stream->response.content_type = cfl_sds_create_len((const char *) value, value_length);

        if (stream->response.content_type == NULL) {
            return -1;
        }
    }
    else if (flb_http_server_strncasecmp(
                name, name_length, "content-length", 0) == 0) {
        strncpy(temporary_buffer,
                (const char *) value,
                http2_lower_value(sizeof(temporary_buffer), value_length + 1));

        temporary_buffer[sizeof(temporary_buffer) - 1] = '\0';

        stream->response.content_length = strtoull(temporary_buffer, NULL, 10);
    }

    result = flb_http_response_set_header(&stream->response,
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
    struct flb_http_client_session  *parent_session;
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
                if (stream->status == HTTP_STREAM_STATUS_RECEIVING_HEADERS) {
                    stream->status = HTTP_STREAM_STATUS_RECEIVING_DATA;
                }
            }
            else {
                if (stream->status == HTTP_STREAM_STATUS_RECEIVING_DATA) {
                    stream->status = HTTP_STREAM_STATUS_RECEIVING_TRAILER;
                }
                //else if
                //stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;
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

        parent_session = (struct flb_http_client_session *) stream->parent;

        if (parent_session == NULL) {
            return -1;
        }

        cfl_list_add(&stream->response._head,
                     &parent_session->response_queue);
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
    return 0;
}

static int http2_data_chunk_recv_callback(nghttp2_session *inner_session,
                                          uint8_t flags,
                                          int32_t stream_id,
                                          const uint8_t *data,
                                          size_t len,
                                          void *user_data)
{
    struct flb_http_client_session  *parent_session;
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

    if (stream->response.body == NULL) {
        stream->response.body = cfl_sds_create_size(len);

        if (stream->response.body == NULL) {
            stream->status = HTTP_STREAM_STATUS_ERROR;

            return -1;
        }

        cfl_sds_set_len(stream->response.body, 0);

        stream->response.body_read_offset = 0;
    }

    resized_buffer = cfl_sds_cat(stream->response.body,
                                    (const char *) data,
                                    len);

    if (resized_buffer == NULL) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        return -1;
    }

    stream->response.body = resized_buffer;
    stream->response.body_read_offset += len;

    if (stream->status == HTTP_STREAM_STATUS_RECEIVING_DATA) {
        if (stream->response.content_length >=
            stream->response.body_read_offset) {
            stream->status = HTTP_STREAM_STATUS_READY;

            if (!cfl_list_entry_is_orphan(&stream->response._head)) {
                cfl_list_del(&stream->response._head);
            }

            parent_session = (struct flb_http_client_session *) stream->parent;

            if (parent_session == NULL) {
                return -1;
            }

            cfl_list_add(&stream->response._head,
                         &parent_session->response_queue);
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

    if (stream->request.body != NULL) {
        body_offset    = stream->request.body_read_offset;
        content_length = cfl_sds_len(stream->request.body) - body_offset;
    }
    else {
        body_offset = 0;
        content_length = 0;
    }

    if (content_length > length) {
        memcpy(buf,
               &stream->request.body[body_offset], length);

        result = length;

        stream->request.body_read_offset += length;
    }
    else {
        if (content_length > 0) {
            memcpy(buf,
                   &stream->request.body[body_offset], content_length);

            stream->request.body_read_offset += content_length;
        }

        result = content_length;

        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

        if (mk_list_is_empty(&stream->request.trailer_headers->entries) != 0) {
            *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        }
    }

    return result;
}

int flb_http2_client_session_init(struct flb_http2_client_session *session)
{
    nghttp2_settings_entry     session_settings[3];
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

    result = nghttp2_session_client_new(&session->inner_session, callbacks, session);

    nghttp2_session_callbacks_del(callbacks);

    if (result != 0) {
        return -2;
    }

    session->initialized = FLB_TRUE;

    session_settings[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    session_settings[0].value = 1;

    session_settings[1].settings_id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE;
    session_settings[1].value = cfl_sds_alloc(session->parent->parent->temporary_buffer);

    session_settings[2].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
    session_settings[2].value = 0;


    result = nghttp2_submit_settings(session->inner_session,
                                     NGHTTP2_FLAG_NONE,
                                     session_settings,
                                     3);

    if (result != 0) {
        return -3;
    }

    result = nghttp2_session_send(session->inner_session);

    if (result != 0) {
        return -4;
    }

    return 0;
}

void flb_http2_client_session_destroy(struct flb_http2_client_session *session)
{
    if (session != NULL) {
        if (session->initialized) {
            nghttp2_session_del(session->inner_session);

            session->initialized = FLB_FALSE;
        }
    }
}

int flb_http2_client_session_ingest(struct flb_http2_client_session *session,
                                    unsigned char *buffer,
                                    size_t length)
{
    ssize_t result;

    result = nghttp2_session_mem_recv(session->inner_session, buffer, length);

    if (result < 0) {
        return HTTP_CLIENT_PROVIDER_ERROR;
    }

    result = nghttp2_session_send(session->inner_session);

    if (result < 0) {
        return HTTP_CLIENT_PROVIDER_ERROR;
    }

    return HTTP_CLIENT_SUCCESS;
}

int flb_http2_request_begin(struct flb_http_request *request)
{
    return 0;
}

int flb_http2_request_commit(struct flb_http_request *request)
{
    struct flb_http_client_session  *parent_session;
    cfl_sds_t                        sds_result;
    struct flb_http2_client_session *session;
    struct flb_http_stream          *stream;
    int                              result;

    char                             content_length_string[21];
    struct mk_list                  *header_iterator;
    const char                      *scheme_as_text;
    const char                      *method_as_text;
    nghttp2_data_provider            data_provider;
    size_t                           header_count;
    size_t                           header_index;
    struct flb_hash_table_entry     *header_entry;
    nghttp2_nv                      *headers;

    parent_session = (struct flb_http_client_session *) request->stream->parent;

    if (parent_session == NULL) {
        return -1;
    }

    session = &parent_session->http2;

    if (session == NULL) {
        return -1;
    }

    stream  = (struct flb_http_stream *) request->stream;

    if (stream == NULL) {
        return -2;
    }

    if (request->host == NULL) {
        return -1;
    }

    if (parent_session->connection->tls_session != NULL) {
        scheme_as_text = "https";
    }
    else {
        scheme_as_text = "http";
    }

    switch (request->method) {
    case HTTP_METHOD_GET:
        method_as_text = "GET";
        break;
    case HTTP_METHOD_POST:
        method_as_text = "POST";
        break;
    case HTTP_METHOD_HEAD:
        method_as_text = "HEAD";
        break;
    case HTTP_METHOD_PUT:
        method_as_text = "PUT";
        break;
    case HTTP_METHOD_DELETE:
        method_as_text = "DELETE";
        break;
    case HTTP_METHOD_OPTIONS:
        method_as_text = "OPTIONS";
        break;
    case HTTP_METHOD_CONNECT:
        method_as_text = "CONNECT";
        break;
    default:
        method_as_text = NULL;
        break;
    }

    if (method_as_text == NULL) {
        return -1;
    }

    if (request->authority == NULL) {
        request->authority = cfl_sds_create(request->host);

        if (request->authority == NULL) {
            return -1;
        }

        sds_result = cfl_sds_printf(&request->authority,
                                    ":%u",
                                    request->port);

        if (sds_result == NULL) {
            return -1;
        }
    }

    header_count = request->headers->total_count + 7;

    headers = flb_calloc(header_count, sizeof(nghttp2_nv));

    if (headers == NULL) {
        return -3;
    }

    header_index = 0;

    headers[header_index].name = (uint8_t *) ":method";
    headers[header_index].namelen = strlen(":method");
    headers[header_index].value = (uint8_t *) method_as_text;
    headers[header_index].valuelen = strlen(method_as_text);

    header_index++;

    headers[header_index].name = (uint8_t *) ":scheme";
    headers[header_index].namelen = strlen(":scheme");
    headers[header_index].value = (uint8_t *) scheme_as_text;
    headers[header_index].valuelen = strlen(scheme_as_text);

    header_index++;

    headers[header_index].name = (uint8_t *) ":authority";
    headers[header_index].namelen = strlen(":authority");
    headers[header_index].value = (uint8_t *) request->authority;
    headers[header_index].valuelen = strlen(request->authority);

    header_index++;

    if (request->method == HTTP_METHOD_OPTIONS &&
        request->path == NULL) {
        headers[header_index].name = (uint8_t *) ":path";
        headers[header_index].namelen = strlen(":path");
        headers[header_index].value = (uint8_t *) "*";
        headers[header_index].valuelen = strlen("*");

        header_index++;
    }
    else if (request->method != HTTP_METHOD_CONNECT) {
        if (request->path == NULL) {
            flb_free(headers);

            return -1;
        }

        headers[header_index].name = (uint8_t *) ":path";
        headers[header_index].namelen = strlen(":path");
        headers[header_index].value = (uint8_t *) request->path;
        headers[header_index].valuelen = strlen(request->path);

        header_index++;
    }

   if(request->user_agent != NULL) {
        headers[header_index].name = (uint8_t *) "User-agent";
        headers[header_index].namelen = strlen("User-agent");
        headers[header_index].value = (uint8_t *) request->user_agent;
        headers[header_index].valuelen = strlen(request->user_agent);

        header_index++;
    }

    if(request->content_type != NULL) {
        headers[header_index].name = (uint8_t *) "Content-type";
        headers[header_index].namelen = strlen("Content-type");
        headers[header_index].value = (uint8_t *) request->content_type;
        headers[header_index].valuelen = strlen(request->content_type);

        header_index++;
    }

    if (request->method == HTTP_METHOD_POST ||
        request->method == HTTP_METHOD_PUT ) {
        snprintf(content_length_string,
                 sizeof(content_length_string) - 1,
                 "%zu",
                 request->content_length);

        content_length_string[sizeof(content_length_string) - 1] = '\0';

        headers[header_index].name = (uint8_t *) "Content-length";
        headers[header_index].namelen = strlen("Content-length");
        headers[header_index].value = (uint8_t *) content_length_string;
        headers[header_index].valuelen = strlen(content_length_string);

        header_index++;
    }

    header_count = request->headers->total_count + header_index;

    mk_list_foreach(header_iterator, &request->headers->entries) {
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

    result = nghttp2_submit_request(session->inner_session,
                                    NULL,
                                    headers,
                                    header_count,
                                    &data_provider,
                                    stream);

    if (result < 0) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        flb_free(headers);

        return -5;
    }

    stream->id = result;

    result = nghttp2_session_send(session->inner_session);

    flb_free(headers);

    if (result != 0) {
        stream->status = HTTP_STREAM_STATUS_ERROR;

        return -8;
    }

    stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;

    return 0;
}
