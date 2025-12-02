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

/*
 * Parseable Output Plugin Header
 * ================================
 * 
 * This header defines the structures, constants, and types for the
 * Parseable output plugin. Parseable is a log analytics system that
 * accepts logs via HTTP POST with JSON payloads.
 *
 * Features:
 * - HTTP/HTTPS transport with TLS support
 * - Gzip compression
 * - Custom HTTP headers
 * - Configurable batch size limits
 * - Retry configuration
 * - Comprehensive metrics (requests, errors, records, bytes)
 * - Multiple JSON date formats
 *
 * For usage examples and configuration details, see README.md
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
#define FLB_PARSEABLE_DEFAULT_BATCH_SIZE  5242880  /* 5MB */

/* HTTP headers */
#define FLB_PARSEABLE_CONTENT_TYPE        "Content-Type"
#define FLB_PARSEABLE_MIME_JSON           "application/json"
#define FLB_PARSEABLE_HEADER_STREAM       "X-P-Stream"
#define FLB_PARSEABLE_HEADER_LOG_SOURCE   "X-P-Log-Source"

/* JSON date format options */
#define FLB_PARSEABLE_JSON_DATE_EPOCH              0
#define FLB_PARSEABLE_JSON_DATE_ISO8601            1
#define FLB_PARSEABLE_JSON_DATE_JAVA_SQL_TIMESTAMP 2

/* Compression options */
#define FLB_PARSEABLE_COMPRESS_NONE       0
#define FLB_PARSEABLE_COMPRESS_GZIP       1

/* Retry limits */
#define FLB_PARSEABLE_RETRY_UNLIMITED     -1
#define FLB_PARSEABLE_RETRY_NONE          0

/* Plugin context structure */
struct flb_out_parseable {
    /* Parseable connection details */
    flb_sds_t host;
    int port;
    flb_sds_t uri;
    flb_sds_t data_type;    /* Data type: logs, metrics, or traces */
    
    /* Parseable-specific headers */
    flb_sds_t stream;       /* X-P-Stream header (required) */
    flb_sds_t log_source;   /* X-P-Log-Source header (optional) */
    flb_sds_t auth_header;  /* Authorization header value */
    
    /* Custom headers */
    struct mk_list *headers;
    
    /* Output format */
    int json_date_format;
    flb_sds_t date_key;
    
    /* Compression */
    int compress_gzip;
    
    /* Batch size limits */
    size_t batch_size;      /* Maximum batch size in bytes */
    
    /* Retry configuration */
    int retry_limit;        /* Maximum number of retries (-1 = unlimited) */
    
    /* Dynamic stream routing (for Kubernetes autodiscovery) */
    int dynamic_stream;     /* Enable dynamic stream from record metadata */
    
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
