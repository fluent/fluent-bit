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

#include <monkey/mk_core.h>
#include <monkey/mk_http.h>

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

#ifndef MK_METHOD_CONNECT
#define MK_METHOD_CONNECT (MK_METHOD_UNKNOWN + 1)
#endif

#define HTTP_PROTOCOL_VERSION_AUTODETECT       -1
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
#define HTTP_METHOD_CONNECT                    MK_METHOD_CONNECT
#define HTTP_METHOD_UNKNOWN                    MK_METHOD_UNKNOWN

#define HTTP_STREAM_ROLE_SERVER                0
#define HTTP_STREAM_ROLE_CLIENT                1

#define HTTP_STREAM_STATUS_SENDING_HEADERS     0
#define HTTP_STREAM_STATUS_SENDING_DATA        1
#define HTTP_STREAM_STATUS_SENDING_TRAILER     2
#define HTTP_STREAM_STATUS_RECEIVING_HEADERS   3
#define HTTP_STREAM_STATUS_RECEIVING_DATA      4
#define HTTP_STREAM_STATUS_RECEIVING_TRAILER   5
#define HTTP_STREAM_STATUS_READY               6
#define HTTP_STREAM_STATUS_PROCESSING          7
#define HTTP_STREAM_STATUS_CLOSED              8
#define HTTP_STREAM_STATUS_ERROR               9

#define HTTP_WWW_AUTHORIZATION_SCHEME_NONE       0
#define HTTP_WWW_AUTHORIZATION_SCHEME_BASIC      (((uint64_t) 1) << 0)
#define HTTP_WWW_AUTHORIZATION_SCHEME_BEARER     (((uint64_t) 1) << 1)
#define HTTP_WWW_AUTHORIZATION_SCHEME_SIGNV4     (((uint64_t) 1) << 2)

#define HTTP_PROXY_AUTHORIZATION_SCHEME_BASIC    10
#define HTTP_PROXY_AUTHORIZATION_SCHEME_BEARER   11

struct flb_http_stream;
struct flb_http_server_session;

struct flb_http_request {
    int                               protocol_version;
    cfl_sds_t                         authority;
    int                               method;
    cfl_sds_t                         path;
    cfl_sds_t                         host;
    uint16_t                          port;
    cfl_sds_t                         query_string;
    struct flb_hash_table            *headers;
    struct flb_hash_table           *trailer_headers;
    cfl_sds_t                         user_agent;
    size_t                            content_length;
    char                             *content_type;
    cfl_sds_t                         body;
    size_t                            body_read_offset;

    struct flb_http_stream           *stream;

    int                               releasable;
    struct cfl_list                   _head;
};

struct flb_http_response {
    int                              protocol_version;
    int                              status;
    cfl_sds_t                        message;
    struct flb_hash_table           *headers;
    struct flb_hash_table           *trailer_headers;
    size_t                           content_length;
    char                            *content_type;
    cfl_sds_t                        body;
    size_t                           body_read_offset;

    struct flb_http_stream          *stream;

    int                              releasable;
    struct cfl_list                  _head;
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

struct flb_aws_provider;

/* HTTP REQUEST */

int flb_http_request_init(struct flb_http_request *request);

struct flb_http_request *flb_http_request_create();

void flb_http_request_destroy(struct flb_http_request *request);

int flb_http_request_commit(struct flb_http_request *request);

char *flb_http_request_get_header(struct flb_http_request *request,
                                  char *name);

int flb_http_request_set_header(struct flb_http_request *request,
                                char *name, size_t name_length,
                                char *value, size_t value_length);

int flb_http_request_unset_header(struct flb_http_request *request,
                                  char *name);

int flb_http_request_set_method(struct flb_http_request *request,
                                int method);

int flb_http_request_set_host(struct flb_http_request *request,
                              char *host);

int flb_http_request_set_port(struct flb_http_request *request,
                              uint16_t port);

int flb_http_request_set_url(struct flb_http_request *request,
                             char *url);

int flb_http_request_set_uri(struct flb_http_request *request,
                             char *uri);

int flb_http_request_set_query_string(struct flb_http_request *request,
                                      char *query_string);

int flb_http_request_set_content_type(struct flb_http_request *request,
                                      char *content_type);

int flb_http_request_set_user_agent(struct flb_http_request *request,
                                    char *user_agent);

int flb_http_request_set_content_length(struct flb_http_request *request,
                                        size_t content_length);

int flb_http_request_set_content_encoding(struct flb_http_request *request,
                                          char *encoding);

int flb_http_request_set_body(struct flb_http_request *request,
                              unsigned char *body, size_t body_length,
                              char *compression_algorithm);

int flb_http_request_set_authorization(struct flb_http_request *request,
                                       int type, ...);

int flb_http_request_compress_body(
    struct flb_http_request *request,
    char *content_encoding_header_value);

int flb_http_request_uncompress_body(
    struct flb_http_request *request);

int flb_http_request_perform_signv4_signature(
        struct flb_http_request *request,
        const char *aws_region,
        const char *aws_service,
        struct flb_aws_provider *aws_provider);

/* HTTP RESPONSE */

int flb_http_response_init(struct flb_http_response *response);

struct flb_http_response *flb_http_response_create();

void flb_http_response_destroy(struct flb_http_response *response);

struct flb_http_response *flb_http_response_begin(
                                struct flb_http_server_session *session,
                                void *stream);

int flb_http_response_commit(struct flb_http_response *response);

char *flb_http_response_get_header(struct flb_http_response *response,
                                  char *name);

int flb_http_response_set_header(struct flb_http_response *response,
                             char *name, size_t name_length,
                             char *value, size_t value_length);

int flb_http_response_unset_header(struct flb_http_response *response,
                                  char *name);

int flb_http_response_set_trailer_header(struct flb_http_response *response,
                                         char *name, size_t name_length,
                                         char *value, size_t value_length);

int flb_http_response_set_status(struct flb_http_response *response,
                             int status);

int flb_http_response_set_message(struct flb_http_response *response,
                              char *message);

int flb_http_response_set_body(struct flb_http_response *response,
                           unsigned char *body, size_t body_length);

int flb_http_response_append_to_body(struct flb_http_response *response,
                                     unsigned char *body, size_t body_length);

int flb_http_response_compress_body(
    struct flb_http_response *response,
    char *content_encoding_header_value);

int flb_http_response_uncompress_body(
    struct flb_http_response *response);


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


const char *flb_http_get_method_string_from_id(int method);

char *flb_http_server_convert_string_to_lowercase(char *input_buffer,
                                                  size_t length);

int flb_http_server_strncasecmp(const uint8_t *first_buffer,
                                size_t first_length,
                                const char *second_buffer,
                                size_t second_length);
#endif
