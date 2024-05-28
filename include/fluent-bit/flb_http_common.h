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

/* These definitions are temporary and should be moved 
 * to monkey. 
 * This fallback has been added to be able to merge this 
 * feature with the current monkey version.
 */

#ifndef MK_HTTP_PROTOCOL_20
#define MK_HTTP_PROTOCOL_20 (20)
#endif

#ifndef MK_HTTP_PROTOCOL_20_STR
#define MK_HTTP_PROTOCOL_20_STR "HTTP/2"
#endif

#define HTTP_PROTOCOL_AUTODETECT              -1
#define HTTP_PROTOCOL_HTTP0                    0
#define HTTP_PROTOCOL_HTTP1                    1
#define HTTP_PROTOCOL_HTTP2                    2

#define HTTP_PROTOCOL_VERSION_09               MK_HTTP_PROTOCOL_09
#define HTTP_PROTOCOL_VERSION_10               MK_HTTP_PROTOCOL_10
#define HTTP_PROTOCOL_VERSION_11               MK_HTTP_PROTOCOL_11
#define HTTP_PROTOCOL_VERSION_20               MK_HTTP_PROTOCOL_20

#define HTTP_METHOD_GET                        MK_METHOD_GET
#define HTTP_METHOD_POST                       MK_METHOD_POST
#define HTTP_METHOD_HEAD                       MK_METHOD_HEAD
#define HTTP_METHOD_PUT                        MK_METHOD_PUT
#define HTTP_METHOD_DELETE                     MK_METHOD_DELETE
#define HTTP_METHOD_OPTIONS                    MK_METHOD_OPTIONS
#define HTTP_METHOD_UNKNOWN                    MK_METHOD_UNKNOWN

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

struct flb_http_request {
    int                               protocol_version;
    int                               method;
    cfl_sds_t                         path;
    cfl_sds_t                         host;
    cfl_sds_t                         query_string;
    struct flb_hash_table            *headers;
    size_t                            content_length;
    char                             *content_type;
    cfl_sds_t                         body;

    struct flb_http_stream           *stream;

    struct cfl_list                   _head;
};

struct flb_http_response {
    int                              status;
    cfl_sds_t                        message;
    struct flb_hash_table           *headers;
    struct flb_hash_table           *trailer_headers;
    size_t                           content_length;
    cfl_sds_t                        body;
    size_t                           body_read_offset;

    struct flb_http_stream          *stream;
};

struct flb_http_stream {
    int32_t                         id;
    int                             role;
    int                             status;

    struct flb_http_request         request;
    struct flb_http_response        response;

    void                           *parent;
    void                           *user_data;

    int                             releasable;
    struct cfl_list                 _head;
};

/* HTTP REQUEST */

int flb_http_request_init(struct flb_http_request *request);

void flb_http_request_destroy(struct flb_http_request *request);

char *flb_http_request_get_header(struct flb_http_request *request,
                                  char *name);

int flb_http_request_set_header(struct flb_http_request *request,
                                char *name, size_t name_length,
                                char *value, size_t value_length);

int flb_http_request_unset_header(struct flb_http_request *request,
                                  char *name);

/* HTTP RESPONSE */

int flb_http_response_init(struct flb_http_response *response);

void flb_http_response_destroy(struct flb_http_response *response);

struct flb_http_response *flb_http_response_begin(
                                struct flb_http_server_session *session, 
                                void *stream);

int flb_http_response_commit(struct flb_http_response *response);

int flb_http_response_set_header(struct flb_http_response *response, 
                             char *name, size_t name_length,
                             char *value, size_t value_length);

int flb_http_response_set_trailer_header(struct flb_http_response *response, 
                                         char *name, size_t name_length,
                                         char *value, size_t value_length);

int flb_http_response_set_status(struct flb_http_response *response, 
                             int status);

int flb_http_response_set_message(struct flb_http_response *response, 
                              char *message);

int flb_http_response_set_body(struct flb_http_response *response, 
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
