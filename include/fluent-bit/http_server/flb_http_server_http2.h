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

#ifndef FLB_HTTP_SERVER_HTTP2
#define FLB_HTTP_SERVER_HTTP2

#include <cfl/cfl_list.h>

#include <nghttp2/nghttp2.h>

struct flb_http_server_session;
struct flb_http_stream;

struct flb_http2_server_session {
    nghttp2_session                *inner_session;
    int                             initialized;
    struct cfl_list                 streams;
    struct flb_http_server_session *parent;
};

/* RESPONSE */

struct flb_http_response *flb_http2_response_begin(
                                struct flb_http2_server_session *session, 
                                struct flb_http_stream *stream);

int flb_http2_response_set_header(struct flb_http_response *response, 
                              char *name, size_t name_length,
                              char *value, size_t value_length);

int flb_http2_response_set_status(struct flb_http_response *response, 
                              int status);

int flb_http2_response_set_body(struct flb_http_response *response, 
                            unsigned char *body, size_t body_length);

int flb_http2_response_commit(struct flb_http_response *response);

/* SESSION */

int flb_http2_server_session_init(struct flb_http2_server_session *session, 
                       struct flb_http_server_session *parent);

void flb_http2_server_session_destroy(struct flb_http2_server_session *session);

int flb_http2_server_session_ingest(struct flb_http2_server_session *session, 
                         unsigned char *buffer, 
                         size_t length);

#endif
