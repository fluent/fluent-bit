/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
#define FLB_PROMETHEUS_REMOTE_WRITE_CREDENTIAL_PREFIX "aws_"
#endif
#endif

/* Plugin context */
struct prometheus_remote_write_context {
    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* AWS Auth */
#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
    int has_aws_auth;
    struct flb_aws_provider *aws_provider;
    const char *aws_region;
    const char *aws_service;
#endif
#endif

    /* Proxy */
    const char *proxy;
    char *proxy_host;
    int proxy_port;

    /* HTTP URI */
    char *uri;
    char *host;
    int port;

    const char *compression;

    /* Log the response payload */
    int log_response_payload;

    /* config reader for 'add_label' */
    struct mk_list *add_labels;

    /* internal labels ready to append */
    struct mk_list kv_labels;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Arbitrary HTTP headers */
    struct mk_list *headers;


    /* instance context */
    struct flb_output_instance *ins;
};

#endif
