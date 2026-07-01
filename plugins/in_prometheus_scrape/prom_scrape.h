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

#ifndef FLB_IN_PROMETHEUS_SCRAPE_H
#define FLB_IN_PROMETHEUS_SCRAPE_H

#include <fluent-bit/flb_input_plugin.h>

#define DEFAULT_URI           "/metrics"
#define HTTP_BUFFER_MAX_SIZE    "10M"

struct prom_scrape
{
    int coll_id;                     /* collector id */
    uint64_t scrape_interval;
    flb_sds_t metrics_path;
    struct flb_upstream *upstream;
    struct flb_input_instance *ins;  /* input plugin instance */
    size_t buffer_max_size;          /* Maximum buffer size */

    /* HTTP Auth */
    flb_sds_t http_user;
    flb_sds_t http_passwd;

    /* Bearer Token Auth */
    flb_sds_t bearer_token;
};

#endif
