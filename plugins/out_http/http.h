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

#ifndef FLB_OUT_HTTP_H
#define FLB_OUT_HTTP_H

#define FLB_HTTP_OUT_MSGPACK        0
#define FLB_HTTP_OUT_JSON           1
#define FLB_HTTP_OUT_JSON_STREAM    2
#define FLB_HTTP_OUT_JSON_LINES     3
#define FLB_HTTP_OUT_GELF           4

#define FLB_JSON_DATE_DOUBLE      0
#define FLB_JSON_DATE_ISO8601     1
#define FLB_JSON_DATE_ISO8601_FMT "%Y-%m-%dT%H:%M:%S"

#define FLB_HTTP_CONTENT_TYPE   "Content-Type"
#define FLB_HTTP_MIME_MSGPACK   "application/msgpack"
#define FLB_HTTP_MIME_JSON      "application/json"

struct flb_out_http {
    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Proxy */
    char *proxy;
    char *proxy_host;
    int proxy_port;

    /* Output format */
    int out_format;

    int json_date_format;
    char *json_date_key;
    size_t json_date_key_len;

    /* HTTP URI */
    char *uri;
    char *host;
    int port;

    /* GELF fields */
    struct flb_gelf_fields gelf_fields;

    /* Include tag in header */
    char *header_tag;
    size_t headertag_len;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Arbitrary HTTP headers */
    struct mk_list headers;
    int headers_cnt;
};

struct out_http_header {
    char *key;
    int key_len;
    char *val;
    int val_len;
    struct mk_list _head;
};

#endif
