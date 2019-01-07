/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

/* Buffer size */
#define FLB_HTTP_BUF_SIZE        2048
#define FLB_HTTP_DATA_SIZE_MAX   4096
#define FLB_HTTP_DATA_CHUNK     32768

/* HTTP Methods */
#define FLB_HTTP_GET         0
#define FLB_HTTP_POST        1
#define FLB_HTTP_PUT         2
#define FLB_HTTP_HEAD        3

/* HTTP Flags */
#define FLB_HTTP_10          1
#define FLB_HTTP_11          2

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
#define FLB_HTTP_HEADER_AUTH         "Authorization"
#define FLB_HTTP_HEADER_CONTENT_TYPE "Content-Type"

struct flb_http_response {
    int status;                /* HTTP response status          */
    int content_length;        /* Content length set by headers */
    int chunked_encoding;      /* Chunked transfer encoding ?   */
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
    char *host;             /* Proxy Host */
};

/* Set a request type */
struct flb_http_client {
    /* Upstream connection */
    struct flb_upstream_conn *u_conn;

    /* Request data */
    int method;
    int flags;
    int header_len;
    int header_size;
    char *header_buf;

    int body_len;
    char *body_buf;

    /* Proxy */
    struct flb_http_proxy proxy;

    /* Response */
    struct flb_http_response resp;
};

struct flb_http_client *flb_http_client(struct flb_upstream_conn *u_conn,
                                        int method, char *uri,
                                        char *body, size_t body_len,
                                        char *host, int port,
                                        char *proxy, int flags);

int flb_http_add_header(struct flb_http_client *c,
                        char *key, size_t key_len,
                        char *val, size_t val_len);
int flb_http_basic_auth(struct flb_http_client *c, char *user, char *passwd);
int flb_http_do(struct flb_http_client *c, size_t *bytes);
void flb_http_client_destroy(struct flb_http_client *c);
int flb_http_buffer_size(struct flb_http_client *c, size_t size);
size_t flb_http_buffer_available(struct flb_http_client *c);
int flb_http_buffer_increase(struct flb_http_client *c, size_t size,
                             size_t *out_size);

#endif
