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

#ifndef FLB_OUT_OPENTELEMETRY_H
#define FLB_OUT_OPENTELEMETRY_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#define FLB_OPENTELEMETRY_CONTENT_TYPE_HEADER_NAME "Content-Type"
#define FLB_OPENTELEMETRY_MIME_PROTOBUF_LITERAL    "application/x-protobuf"

/*
 * This lets you send log records in batches instead of a request per log record
 * It might be removed in furthur versions since if we have a large number of
 * log records, and a later batch fails, Fluent Bit will retry ALL the batches,
 * including the ones that succeeded. This is not ideal.
 */
#define DEFAULT_LOG_RECORD_BATCH_SIZE "1000"

struct opentelemetry_body_key {
    flb_sds_t key;
    struct flb_record_accessor *ra;
    struct mk_list _head;
};

/* Plugin context */
struct opentelemetry_context {
    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Proxy */
    const char *proxy;
    char *proxy_host;
    int proxy_port;

    /* HTTP URI */
    char *traces_uri;
    char *metrics_uri;
    char *logs_uri;
    char *host;
    int port;

    /* record metadata parsing */
    flb_sds_t logs_metadata_key;

    /* metadata keys */
    flb_sds_t logs_observed_timestamp_metadata_key;
    struct flb_record_accessor *ra_observed_timestamp_metadata;

    flb_sds_t logs_timestamp_metadata_key;
    struct flb_record_accessor *ra_timestamp_metadata;

    flb_sds_t logs_severity_text_metadata_key;
    struct flb_record_accessor *ra_severity_text_metadata;

    flb_sds_t logs_severity_number_metadata_key;
    struct flb_record_accessor *ra_severity_number_metadata;

    flb_sds_t logs_trace_flags_metadata_key;
    struct flb_record_accessor *ra_trace_flags_metadata;

    flb_sds_t logs_span_id_metadata_key;
    struct flb_record_accessor *ra_span_id_metadata;

    flb_sds_t logs_trace_id_metadata_key;
    struct flb_record_accessor *ra_trace_id_metadata;

    flb_sds_t logs_attributes_metadata_key;
    struct flb_record_accessor *ra_attributes_metadata;

    flb_sds_t logs_instrumentation_scope_metadata_key;
    flb_sds_t logs_resource_metadata_key;

    /* otel body keys */
    flb_sds_t logs_span_id_message_key;
    struct flb_record_accessor *ra_span_id_message;

    flb_sds_t logs_trace_id_message_key;
    struct flb_record_accessor *ra_trace_id_message;

    flb_sds_t logs_severity_text_message_key;
    struct flb_record_accessor *ra_severity_text_message;

    flb_sds_t logs_severity_number_message_key;
    struct flb_record_accessor *ra_severity_number_message;

    /* Number of logs to flush at a time */
    int batch_size;

    /* Log the response paylod */
    int log_response_payload;

    /* config reader for 'add_label' */
    struct mk_list *add_labels;

    /*
     * list of linked list body keys given at configuration: note this list is just a slist,
     * of strings, once is parsed, it populate the final list in 'log_body_key_list'
     */
    struct mk_list *log_body_key_list_str;

    /* head of linked list body keys populated once log_body_key_list_str is parsed */
    struct mk_list log_body_key_list;

    /* boolean that defines if remaining keys of logs_body_key are set as attributes */
    int logs_body_key_attributes;

    /* internal labels ready to append */
    struct mk_list kv_labels;

    /* special accessor with list of patterns used to populate log metadata */
    struct flb_mp_accessor *mp_accessor;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Arbitrary HTTP headers */
    struct mk_list *headers;


    /* instance context */
    struct flb_output_instance *ins;

    /* Compression mode (gzip) */
    int compress_gzip;

    /* FLB/OTLP Record accessor patterns */
    struct flb_record_accessor *ra_meta_schema;
    struct flb_record_accessor *ra_meta_resource_id;
    struct flb_record_accessor *ra_meta_scope_id;
    struct flb_record_accessor *ra_resource_attr;
    struct flb_record_accessor *ra_resource_schema_url;

    struct flb_record_accessor *ra_scope_name;
    struct flb_record_accessor *ra_scope_version;
    struct flb_record_accessor *ra_scope_attr;

    /* log: metadata components coming from OTLP */
    struct flb_record_accessor *ra_log_meta_otlp_observed_ts;
    struct flb_record_accessor *ra_log_meta_otlp_timestamp;
    struct flb_record_accessor *ra_log_meta_otlp_severity_number;
    struct flb_record_accessor *ra_log_meta_otlp_severity_text;
    struct flb_record_accessor *ra_log_meta_otlp_attr;
    struct flb_record_accessor *ra_log_meta_otlp_trace_id;
    struct flb_record_accessor *ra_log_meta_otlp_span_id;
    struct flb_record_accessor *ra_log_meta_otlp_trace_flags;
};

int opentelemetry_http_post(struct opentelemetry_context *ctx,
                            const void *body, size_t body_len,
                            const char *tag, int tag_len,
                            const char *uri);
#endif
