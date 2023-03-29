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

#ifndef FLB_HTTP_CLIENT_H
#define FLB_HTTP_CLIENT_H

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_callback.h>

/* Buffer size */
#define FLB_HTTP_BUF_SIZE        2048
#define FLB_HTTP_DATA_SIZE_MAX   4096
#define FLB_HTTP_DATA_CHUNK     32768

/* HTTP Methods */
#define FLB_HTTP_GET         0
#define FLB_HTTP_POST        1
#define FLB_HTTP_PUT         2
#define FLB_HTTP_HEAD        3
#define FLB_HTTP_CONNECT     4
#define FLB_HTTP_PATCH       5

/* HTTP Flags */
#define FLB_HTTP_10          1
#define FLB_HTTP_11          2
#define FLB_HTTP_KA         16

/* Proxy */
#define FLB_HTTP_PROXY_NONE       0
#define FLB_HTTP_PROXY_HTTP       1
#define FLB_HTTP_PROXY_HTTPS      2

/* Internal codes */
#define FLB_HTTP_ERROR           -1
#define FLB_HTTP_MORE             0
#define FLB_HTTP_OK               1
#define FLB_HTTP_NOT_FOUND        2 /* header not found */

/* Useful headers */
#define FLB_HTTP_HEADER_AUTH             "Authorization"
#define FLB_HTTP_HEADER_PROXY_AUTH       "Proxy-Authorization"
#define FLB_HTTP_HEADER_CONTENT_TYPE     "Content-Type"
#define FLB_HTTP_HEADER_CONTENT_ENCODING "Content-Encoding"
#define FLB_HTTP_HEADER_CONNECTION       "Connection"
#define FLB_HTTP_HEADER_KA               "keep-alive"

struct flb_http_response {
    int status;                /* HTTP response status          */
    int content_length;        /* Content length set by headers */
    int chunked_encoding;      /* Chunked transfer encoding ?   */
    int connection_close;      /* connection: close ?           */
    long chunked_cur_size;
    long chunked_exp_size;     /* expected chunked size         */
    char *chunk_processed_end; /* Position to mark last chunk   */
    char *headers_end;         /* Headers end (\r\n\r\n)        */

    /* Payload: body response: reference to 'data' */
    char *payload;
    size_t payload_size;

    /* Buffer to store server response */
    char   *data;
    size_t data_len;
    size_t data_size;
    size_t data_size_max;
};

/* It hold information about a possible HTTP proxy set by the caller */
struct flb_http_proxy {
    int type;               /* One of FLB_HTTP_PROXY_ macros */
    int port;               /* TCP Port */
    const char *host;       /* Proxy Host */
};

/* HTTP Debug context */
struct flb_http_debug {
    /* HTTP request headers */
    int debug_request_headers;          /* debug HTTP request headers   */
    void (*cb_debug_request_headers);   /* callback to pass raw headers */

    /* HTTP request payload */
    int debug_request_payload;          /* debug HTTP request payload   */
    int (*cb_debug_request_payload);
};

/* Set a request type */
struct flb_http_client {
    /* Upstream connection */
    struct flb_connection *u_conn;

    /* Request data */
    int method;
    int flags;
    int header_len;
    int header_size;
    char *header_buf;

    /* Config */
    int allow_dup_headers;          /* allow duplicated headers      */

    /* incoming parameters */
    const char *uri;
    const char *query_string;
    const char *host;
    int port;

    /* payload */
    int body_len;
    const char *body_buf;

    struct mk_list headers;

    /* Proxy */
    struct flb_http_proxy proxy;

    /* Response */
    struct flb_http_response resp;

    /* Reference to Callback context */
    void *cb_ctx;
};

void flb_http_client_debug(struct flb_http_client *c,
                           struct flb_callback *cb_ctx);

struct flb_http_client *flb_http_client(struct flb_connection *u_conn,
                                        int method, const char *uri,
                                        const char *body, size_t body_len,
                                        const char *host, int port,
                                        const char *proxy, int flags);

int flb_http_add_header(struct flb_http_client *c,
                        const char *key, size_t key_len,
                        const char *val, size_t val_len);
flb_sds_t flb_http_get_header(struct flb_http_client *c,
                              const char *key, size_t key_len);
int flb_http_basic_auth(struct flb_http_client *c,
                        const char *user, const char *passwd);
int flb_http_proxy_auth(struct flb_http_client *c,
                        const char *user, const char *passwd);
int flb_http_bearer_auth(struct flb_http_client *c,
                        const char *token);
int flb_http_set_keepalive(struct flb_http_client *c);
int flb_http_set_content_encoding_gzip(struct flb_http_client *c);
int flb_http_set_callback_context(struct flb_http_client *c,
                                  struct flb_callback *cb_ctx);

int flb_http_do(struct flb_http_client *c, size_t *bytes);
int flb_http_client_proxy_connect(struct flb_connection *u_conn);
void flb_http_client_destroy(struct flb_http_client *c);
int flb_http_buffer_size(struct flb_http_client *c, size_t size);
size_t flb_http_buffer_available(struct flb_http_client *c);
int flb_http_buffer_increase(struct flb_http_client *c, size_t size,
                             size_t *out_size);
int flb_http_strip_port_from_host(struct flb_http_client *c);
int flb_http_allow_duplicated_headers(struct flb_http_client *c, int allow);
int flb_http_client_debug_property_is_valid(char *key, char *val);

#endif
