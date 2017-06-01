/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#define FLB_HTTP_OUT_MSGPACK    0
#define FLB_HTTP_OUT_JSON       1

#define FLB_HTTP_CONTENT_TYPE   "Content-Type"
#define FLB_HTTP_MIME_MSGPACK   "application/msgpack"
#define FLB_HTTP_MIME_JSON      "application/json"

struct flb_out_http_config {
    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Proxy */
    char *proxy;
    char *proxy_host;
    int proxy_port;

    /* Output format */
    int out_format;

    /* HTTP URI */
    char *uri;
    char *host;
    int  port;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;
};

#endif
