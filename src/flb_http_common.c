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
#include <fluent-bit/flb_http_common.h>

/* HTTP REQUEST */

int flb_http_request_init(struct flb_http_request *request)
{
    flb_http_request_destroy(request);

    cfl_list_entry_init(&request->_head);

    request->headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (request->headers == NULL) {
        return -1;
    }

    return 0;
}

void flb_http_request_destroy(struct flb_http_request *request)
{
    if (request->path != NULL) {
         cfl_sds_destroy(request->path);
    }

    if (request->host != NULL) {
         cfl_sds_destroy(request->host);
    }

    if (request->content_type != NULL) {
         cfl_sds_destroy(request->content_type);
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

    memset(request, 0, sizeof(struct flb_http_request));
}

char *flb_http_request_get_header(struct flb_http_request *request,
                                  char *name)
{
    char   *lowercase_name;
    size_t value_length;
    int    result;
    void  *value;

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, strlen(name));

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

int flb_http_request_set_header(struct flb_http_request *request,
                                char *name, size_t name_length,
                                char *value, size_t value_length) 
{
    char  *lowercase_name;
    int    result;

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, name_length);

    if (lowercase_name == NULL) {
        return -1;
    }

    if (name_length == 0) {
        name_length = strlen(name);
    }

    if (value_length == 0) {
        if (value[0] == '\0') {
            value_length = 1; 
        }
        else {
            value_length = strlen(value);
        }
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

int flb_http_request_unset_header(struct flb_http_request *request,
                                  char *name)
{
    char  *lowercase_name;
    int    result;

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, strlen(name));

    if (lowercase_name == NULL) {
        return -1;
    }

    result = flb_hash_table_del(request->headers, 
                                (const char *) lowercase_name);

    flb_free(lowercase_name);

    if (result == -1) {
        return -1;
    }

    return 0;
}

/* HTTP RESPONSE */

int flb_http_response_init(struct flb_http_response *response)
{
    flb_http_response_destroy(response);

    response->headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (response->headers == NULL) {
        return -1;
    }

    response->trailer_headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (response->trailer_headers == NULL) {
        flb_http_response_destroy(response);

        return -1;
    }

    return 0;
}

void flb_http_response_destroy(struct flb_http_response *response)
{
    if (response->message != NULL) {
         cfl_sds_destroy(response->message);
    }

    if (response->body != NULL) {
         cfl_sds_destroy(response->body);
    }

    if (response->headers != NULL) {
        flb_hash_table_destroy(response->headers);
    }

    if (response->trailer_headers != NULL) {
         flb_hash_table_destroy(response->trailer_headers);
    }

    memset(response, 0, sizeof(struct flb_http_response));
}

struct flb_http_response *flb_http_response_begin(
                                struct flb_http_server_session *session, 
                                void *stream)
{
    if (session->version == HTTP_PROTOCOL_HTTP2) {
        return flb_http2_response_begin(&session->http2, stream);
    }
    else {
        return flb_http1_response_begin(&session->http1, stream);
    }
}

int flb_http_response_commit(struct flb_http_response *response)
{
    struct flb_http_server_session *session;

    if (response->body == NULL) {
        flb_http_response_set_header(response, 
                                     "content-length", 
                                     strlen("content-length"),
                                     "0", 
                                     1);
    }

    session = (struct flb_http_server_session *) response->stream->parent;

    if (session->version == HTTP_PROTOCOL_HTTP2) {
        return flb_http2_response_commit(response);
    }

    return flb_http1_response_commit(response);
}

int flb_http_response_set_header(struct flb_http_response *response, 
                             char *name, size_t name_length,
                             char *value, size_t value_length)
{
    struct flb_http_server_session *session;

    if (name_length == 0) {
        name_length = strlen(name);
    }

    if (value_length == 0) {
        if (value[0] == '\0') {
            value_length = 1; 
        }
        else {
            value_length = strlen(value);
        }
    }

    session = (struct flb_http_server_session *) response->stream->parent;

    if (session->version == HTTP_PROTOCOL_HTTP2) {
        return flb_http2_response_set_header(response, 
                                         name, name_length, 
                                         value, value_length);
    }
    else {
        return flb_http1_response_set_header(response, 
                                         name, name_length, 
                                         value, value_length);
    }
}

int flb_http_response_set_trailer_header(struct flb_http_response *response, 
                                         char *name, size_t name_length,
                                         char *value, size_t value_length)
{
    char  *lowercase_name;
    int    result;

    if (name_length == 0) {
        name_length = strlen(name);
    }

    if (value_length == 0) {
        if (value[0] == '\0') {
            value_length = 1; 
        }
        else {
            value_length = strlen(value);
        }
    }

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, name_length);

    if (lowercase_name == NULL) {
        return -1;
    }

    result = flb_hash_table_add(response->trailer_headers, 
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

int flb_http_response_set_status(struct flb_http_response *response, 
                             int status)
{
    struct flb_http_server_session *session;

    session = (struct flb_http_server_session *) response->stream->parent;

    response->status = status;

    if (session->version == HTTP_PROTOCOL_HTTP2) {
        return flb_http2_response_set_status(response, status);
    }

    return flb_http1_response_set_status(response, status);
}

int flb_http_response_set_message(struct flb_http_response *response, 
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

int flb_http_response_set_body(struct flb_http_response *response, 
                           unsigned char *body, size_t body_length)
{
    struct flb_http_server_session *session;

    session = (struct flb_http_server_session *) response->stream->parent;

    response->body = cfl_sds_create_len((const char *) body, body_length);
    
    if (session->version == HTTP_PROTOCOL_HTTP2) {
        return flb_http2_response_set_body(response, body, body_length);
    }

    return flb_http1_response_set_body(response, body, body_length);
}

/* HTTP STREAM */

int flb_http_stream_init(struct flb_http_stream *stream,
                     void *parent, 
                     int32_t stream_id,
                     int role,
                     void *user_data)
{
    int result;

    stream->id = stream_id;
    stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;

    result = flb_http_request_init(&stream->request);

    if (result != 0) {
        return -1;
    }

    result = flb_http_response_init(&stream->response);

    if (result != 0) {
        return -2;
    }

    stream->role = role;
    stream->parent = parent;
    stream->user_data = user_data;

    stream->request.stream  = stream;
    stream->response.stream = stream;

    return 0;
}

struct flb_http_stream *flb_http_stream_create(void *parent, 
                                           int32_t stream_id,
                                           int role,
                                           void *user_data)
{
    struct flb_http_stream *stream;
    int                     result;

    stream = flb_calloc(1, sizeof(struct flb_http_stream));

    if (stream == NULL) {
        return NULL;
    }

    stream->releasable = FLB_TRUE;

    result = flb_http_stream_init(stream, parent, stream_id, role, user_data);

    if (result != 0) {
        flb_http_stream_destroy(stream);
    }

    return stream;
}

void flb_http_stream_destroy(struct flb_http_stream *stream)
{
    if (stream != NULL) {
        if (!cfl_list_entry_is_orphan(&stream->_head)) {
            cfl_list_del(&stream->_head);
        }

        flb_http_request_destroy(&stream->request);
        flb_http_response_destroy(&stream->response);

        if (stream->releasable) {
          flb_free(stream);
        }
    }
}
