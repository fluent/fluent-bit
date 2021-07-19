/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_PROMETHEUS_REMOTE_WRITE_H
#define FLB_PROMETHEUS_REMOTE_WRITE_H

#include <fluent-bit/flb_output_plugin.h>

#define FLB_PROMETHEUS_REMOTE_WRITE_CONTENT_TYPE_HEADER_NAME "Content-Type"
#define FLB_PROMETHEUS_REMOTE_WRITE_MIME_PROTOBUF_LITERAL    "application/x-protobuf"
#define FLB_PROMETHEUS_REMOTE_WRITE_VERSION_HEADER_NAME      "X-Prometheus-Remote-Write-Version"
#define FLB_PROMETHEUS_REMOTE_WRITE_VERSION_LITERAL          "0.1.0"

/* Plugin context */
struct prometheus_remote_write_context {
    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Proxy */
    const char *proxy;
    char *proxy_host;
    int proxy_port;

    /* HTTP URI */
    char *uri;
    char *host;
    int port;

    /* Log the response paylod */
    int log_response_payload;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Arbitrary HTTP headers */
    struct mk_list *headers;

    /* instance context */
    struct flb_output_instance *ins;
};

#endif
