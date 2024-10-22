/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_OUT_DATADOG_H
#define FLB_OUT_DATADOG_H

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>

#define FLB_DATADOG_DEFAULT_HOST      "http-intake.logs.datadoghq.com"
#define FLB_DATADOG_DEFAULT_PORT      443
#define FLB_DATADOG_DEFAULT_TIME_KEY  "timestamp"
#define FLB_DATADOG_DEFAULT_TAG_KEY   "tagkey"
#define FLB_DATADOG_DEFAULT_LOG_KEY   "log"
#define FLB_DATADOG_DD_HOSTNAME_KEY   "hostname"
#define FLB_DATADOG_DD_SOURCE_KEY     "ddsource"
#define FLB_DATADOG_DD_SERVICE_KEY    "service"
#define FLB_DATADOG_DD_TAGS_KEY       "ddtags"
#define FLB_DATADOG_DD_MESSAGE_KEY    "message"

#define FLB_DATADOG_REMAP_PROVIDER    "ecs"
#define FLB_DATADOG_TAG_SEPERATOR     ","

#define FLB_DATADOG_API_HDR             "DD-API-KEY"
#define FLB_DATADOG_ORIGIN_HDR          "DD-EVP-ORIGIN"
#define FLB_DATADOG_ORIGIN_VERSION_HDR  "DD-EVP-ORIGIN-VERSION"

#define FLB_DATADOG_CONTENT_TYPE   "Content-Type"
#define FLB_DATADOG_MIME_JSON      "application/json"

struct flb_out_datadog {

    /* Proxy */
    flb_sds_t proxy;
    char *proxy_host;
    int proxy_port;

    /* Configuration */
    flb_sds_t scheme;
    flb_sds_t host;
    int port;
    flb_sds_t uri;
    flb_sds_t api_key;
    int include_tag_key;
    flb_sds_t tag_key;
    struct mk_list *headers;
    bool remap;

    /* final result */
    flb_sds_t json_date_key;
    int nb_additional_entries;
    flb_sds_t dd_source;
    flb_sds_t dd_service;
    flb_sds_t dd_hostname;
    flb_sds_t dd_tags;
    flb_sds_t dd_message_key;

    /* Compression mode (gzip) */
    int compress_gzip;

    /* Upstream connection to the backend server */
    struct flb_upstream *upstream;

    /* Plugin instance reference */
    struct flb_output_instance *ins;
};

#endif // FLB_OUT_DATADOG_H
