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

#ifndef FLB_IN_HTTP_CONN
#define FLB_IN_HTTP_CONN

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_hash_table.h>

#include <monkey/mk_http.h>
#include <monkey/mk_http_parser.h>
#include <monkey/mk_utils.h>

#include <cfl/cfl_list.h>
#include <cfl/cfl_sds.h>

#include <nghttp2/nghttp2.h>

#define HTTP_SERVER_INITIAL_BUFFER_SIZE (10 * 1024)
#define HTTP_SERVER_MAXIMUM_BUFFER_SIZE (10 * (1000 * 1024))

#define HTTP_PROTOCOL_AUTODETECT 0
#define HTTP_PROTOCOL_HTTP1      1
#define HTTP_PROTOCOL_HTTP2      2

#define HTTP2_STREAM_STATUS_RECEIVING_HEADERS  0
#define HTTP2_STREAM_STATUS_RECEIVING_DATA     1
#define HTTP2_STREAM_STATUS_READY              2
#define HTTP2_STREAM_STATUS_PROCESSING         3
#define HTTP2_STREAM_STATUS_CLOSED             4
#define HTTP2_STREAM_STATUS_ERROR              5

#define HTTP_SERVER_SUCCESS                    0
#define HTTP_SERVER_PROVIDER_ERROR            -1

struct http_session;

struct http_request {
    int                    method;
    cfl_sds_t              path;
    cfl_sds_t              host;
    cfl_sds_t              query_string;
    struct flb_hash_table *headers;
    size_t                 content_length;
    cfl_sds_t              body;

    void                  *stream;
    struct http_session   *session;

    struct cfl_list        _head;
};

struct http_response {
    int                    status;
    cfl_sds_t              message;
    struct flb_hash_table *headers;
    size_t                 content_length;
    cfl_sds_t              body;
    size_t                 body_read_offset;

    void                  *stream;
    struct http_session   *session;
};

struct http2_stream {
    int32_t                id;
    int                    status;

    struct http_request    request;
    struct http_response   response;

    int                    releasable;
    struct cfl_list        _head;
};

struct http1_stream {
    struct http_response   response;
    
    struct mk_http_request request;
    struct mk_http_parser  parser;
    int                    status;
};

struct http2_session {
    nghttp2_session       *inner_session;
    struct cfl_list        streams;
    struct http_session   *parent;
};

struct http1_session {
    struct mk_http_session inner_session;
    struct mk_server       inner_server;
    struct http1_stream    stream;
    struct http_session   *parent;
};

struct http_session {
    struct http1_session  http1;
    struct http2_session  http2;

    int                   version;
    struct cfl_list       request_queue;

    cfl_sds_t             incoming_data;
    cfl_sds_t             outgoing_data;

    struct flb_connection *connection;
    int                    releasable;
};

struct http_conn {
    struct flb_connection *connection;
    struct http_session    session_;

    void                  *ctx;         /* Plugin parent context             */
    struct mk_list         _head;       /* link to flb_http->connections     */
};

struct http_conn *http2_conn_add(struct flb_connection *connection, struct flb_http *ctx);
int http2_conn_del(struct http_conn *conn);
void http2_conn_release_all(struct flb_http *ctx);


#endif
