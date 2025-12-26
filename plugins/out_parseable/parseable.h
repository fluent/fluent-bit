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

#ifndef FLB_OUT_PARSEABLE_H
#define FLB_OUT_PARSEABLE_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>
#include <cmetrics/cmetrics.h>

/* Default configuration values */
#define FLB_PARSEABLE_DEFAULT_HOST        "127.0.0.1"
#define FLB_PARSEABLE_DEFAULT_PORT        8000
#define FLB_PARSEABLE_DEFAULT_TIME_KEY    "timestamp"

/* HTTP headers */
#define FLB_PARSEABLE_CONTENT_TYPE        "Content-Type"
#define FLB_PARSEABLE_MIME_JSON           "application/json"
#define FLB_PARSEABLE_HEADER_STREAM       "X-P-Stream"
#define FLB_PARSEABLE_HEADER_LOG_SOURCE   "X-P-Log-Source"

/* Plugin context structure */
struct flb_out_parseable {
    /* Parseable configuration */
    flb_sds_t uri;
    flb_sds_t data_type;
    flb_sds_t stream;
    flb_sds_t log_source;
    flb_sds_t auth_header;

    /* Custom headers */
    struct mk_list *headers;

    /* Output format */
    int json_date_format;
    flb_sds_t date_key;

    /* Compression */
    int compress_gzip;

    /* Batch size limit */
    size_t batch_size;

    /* Retry configuration */
    int retry_limit;

    /* Dynamic stream routing */
    int dynamic_stream;

    /* Kubernetes metadata enrichment */
    int enrich_kubernetes;

    /* Metrics */
    struct cmt_counter *cmt_requests_total;
    struct cmt_counter *cmt_errors_total;
    struct cmt_counter *cmt_records_total;
    struct cmt_counter *cmt_bytes_total;
    struct cmt_gauge *cmt_batch_size_bytes;

    /* Upstream connection */
    struct flb_upstream *u;

    /* Plugin instance reference */
    struct flb_output_instance *ins;
};

#endif /* FLB_OUT_PARSEABLE_H */
