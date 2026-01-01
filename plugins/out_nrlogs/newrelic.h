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

#ifndef FLB_OUT_NEWRELIC_H
#define FLB_OUT_NEWRELIC_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_upstream.h>

#define FLB_NEWRELIC_BASE_URI  "https://log-api.newrelic.com/log/v1"

#define FLB_NEWRELIC_CT        "Content-Type"
#define FLB_NEWRELIC_CT_JSON   "application/json"

struct flb_newrelic {
    /* Incoming Configuration Properties */
    flb_sds_t base_uri;
    flb_sds_t api_key;
    flb_sds_t license_key;
    flb_sds_t compress;

    /* Internal parsed URL */
    char *nr_protocol;
    char *nr_host;
    int   nr_port;
    char *nr_uri;
    int   compress_gzip;

    /* Upstream Context */
    struct flb_upstream *u;

    /* Plugin instance */
    struct flb_output_instance *ins;
};

#endif
