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

#ifndef FLB_HTTP_COMMON
#define FLB_HTTP_COMMON

#include <fluent-bit/flb_hash_table.h>

#include <cfl/cfl_list.h>
#include <cfl/cfl_sds.h>

#define HTTP_PROTOCOL_AUTODETECT               0
#define HTTP_PROTOCOL_HTTP1                    1
#define HTTP_PROTOCOL_HTTP2                    2

#define HTTP_STREAM_ROLE_SERVER                0
#define HTTP_STREAM_ROLE_CLIENT                1

#define HTTP_STREAM_STATUS_RECEIVING_HEADERS   0
#define HTTP_STREAM_STATUS_RECEIVING_DATA      1
#define HTTP_STREAM_STATUS_READY               2
#define HTTP_STREAM_STATUS_PROCESSING          3
#define HTTP_STREAM_STATUS_CLOSED              4
#define HTTP_STREAM_STATUS_ERROR               5

struct flb_http_stream;
struct flb_http_server_session;

struct flb_http_request_ng {
    int                               method;
    cfl_sds_t                         path;
    cfl_sds_t                         host;
    cfl_sds_t                         query_string;
    struct flb_hash_table            *headers;
    size_t                            content_length;
    cfl_sds_t                         body;

    struct flb_http_stream           *stream;

    struct cfl_list                   _head;
};

struct flb_http_response_ng {
    int                              status;
    cfl_sds_t                        message;
    struct flb_hash_table           *headers;
    size_t                           content_length;
    cfl_sds_t                        body;
    size_t                           body_read_offset;

    struct flb_http_stream          *stream;
};

struct flb_http_stream {
    int32_t                         id;
    int                             role;
    int                             status;

    struct flb_http_request_ng      request;
    struct flb_http_response_ng     response;

    void                           *parent;
    void                           *user_data;

    int                             releasable;
    struct cfl_list                 _head;
};

/* HTTP REQUEST */

int flb_http_request_init(struct flb_http_request_ng *request);

void flb_http_request_destroy(struct flb_http_request_ng *request);

char *flb_http_request_get_header(struct flb_http_request_ng *request,
                                  char *name);

int flb_http_request_set_header(struct flb_http_request_ng *request,
                                char *name, size_t name_length,
                                char *value, size_t value_length);

/* HTTP RESPONSE */

int flb_http_response_init(struct flb_http_response_ng *response);

void flb_http_response_destroy(struct flb_http_response_ng *response);

struct flb_http_response_ng *flb_http_response_begin(
                                struct flb_http_server_session *session, 
                                void *stream);

int flb_http_response_commit(struct flb_http_response_ng *response);

int flb_http_response_set_header(struct flb_http_response_ng *response, 
                             char *name, size_t name_length,
                             char *value, size_t value_length);

int flb_http_response_set_status(struct flb_http_response_ng *response, 
                             int status);

int flb_http_response_set_message(struct flb_http_response_ng *response, 
                              char *message);

int flb_http_response_set_body(struct flb_http_response_ng *response, 
                           unsigned char *body, size_t body_length);

/* HTTP STREAM */

int flb_http_stream_init(struct flb_http_stream *stream,
                     void *parent, 
                     int32_t stream_id,
                     int role,
                     void *user_data);

struct flb_http_stream *flb_http_stream_create(void *parent, 
                                           int32_t stream_id,
                                           int role,
                                           void *user_data);

void flb_http_stream_destroy(struct flb_http_stream *stream);

#endif
