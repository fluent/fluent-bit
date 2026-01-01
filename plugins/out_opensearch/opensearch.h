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

#ifndef FLB_OUT_OPENSEARCH_H
#define FLB_OUT_OPENSEARCH_H

/* config defaults */
#define FLB_OS_DEFAULT_HOST       "127.0.0.1"
#define FLB_OS_DEFAULT_PORT       92000
#define FLB_OS_DEFAULT_INDEX      "fluent-bit"
#define FLB_OS_DEFAULT_TYPE       "_doc"
#define FLB_OS_DEFAULT_PREFIX     "logstash"
#define FLB_OS_DEFAULT_TIME_FMT   "%Y.%m.%d"
#define FLB_OS_DEFAULT_TIME_KEY   "@timestamp"
#define FLB_OS_DEFAULT_TIME_KEYF  "%Y-%m-%dT%H:%M:%S"
#define FLB_OS_DEFAULT_TAG_KEY    "flb-key"
#define FLB_OS_DEFAULT_HTTP_MAX   "512k"
#define FLB_OS_WRITE_OP_INDEX     "index"
#define FLB_OS_WRITE_OP_CREATE    "create"
#define FLB_OS_WRITE_OP_UPDATE    "update"
#define FLB_OS_WRITE_OP_UPSERT    "upsert"

/* macros */
#define FLB_OS_HEADER_SIZE        1024
#define OS_BULK_CHUNK      4096  /* Size of buffer chunks    */
#define OS_BULK_HEADER      165  /* Bulk API prefix line  */

/* Bulk formats */
#define OS_BULK_INDEX_FMT            "{\"%s\":{\"_index\":\"%s\",\"_type\":\"%s\"}}\n"
#define OS_BULK_INDEX_FMT_ID         "{\"%s\":{\"_index\":\"%s\",\"_type\":\"%s\",\"_id\":\"%s\"}}\n"
#define OS_BULK_INDEX_FMT_NO_TYPE    "{\"%s\":{\"_index\":\"%s\"}}\n"
#define OS_BULK_INDEX_FMT_ID_NO_TYPE "{\"%s\":{\"_index\":\"%s\",\"_id\":\"%s\"}}\n"

/* Bulk write-type operations */
#define OS_BULK_UPDATE_OP_BODY       "{\"doc\":"
#define OS_BULK_UPSERT_OP_BODY       "{\"doc_as_upsert\":true,\"doc\":"

/* Supported compression algorithms */
#define FLB_OS_COMPRESSION_NONE 0
#define FLB_OS_COMPRESSION_GZIP 1

struct flb_opensearch {
    /* OpenSearch index (database) and type (table) */
    flb_sds_t index;
    struct flb_record_accessor *ra_index;

    char *type;
    int suppress_type_name;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* AWS Auth */
#ifdef FLB_HAVE_AWS
    int has_aws_auth;
    char *aws_region;
    char *aws_sts_endpoint;
    char *aws_profile;
    struct flb_aws_provider *aws_provider;
    struct flb_aws_provider *base_aws_provider;
    /* tls instances can't be re-used; aws provider requires a separate one */
    struct flb_tls *aws_tls;
    /* one for the standard chain provider, one for sts assume role */
    struct flb_tls *aws_sts_tls;
    char *aws_session_name;
    char *aws_service_name;
    struct mk_list *aws_unsigned_headers;
#endif

    /* HTTP Client Setup */
    size_t buffer_size;

    /* If enabled, replace field name dots with underscore */
    int replace_dots;

    int trace_output;
    int trace_error;

    /*
     * Logstash compatibility options
     * ==============================
     */

    /* enabled/disabled */
    int logstash_format;
    int generate_id;
    int current_time_index;

    /* prefix */
    flb_sds_t logstash_prefix;
    flb_sds_t logstash_prefix_separator;

    /* prefix key */
    flb_sds_t logstash_prefix_key;

    /* date format */
    flb_sds_t logstash_dateformat;

    /* time key */
    flb_sds_t time_key;

    /* time key format */
    flb_sds_t time_key_format;

    /* time key nanoseconds */
    int time_key_nanos;

    /* write operation config value */
    flb_sds_t write_operation;

    /* write operation / action */
    char *action;

    /* id_key */
    flb_sds_t id_key;
    struct flb_record_accessor *ra_id_key;

    /* include_tag_key */
    int include_tag_key;
    flb_sds_t tag_key;

    /* HTTP API */
    char uri[1024];

    struct flb_record_accessor *ra_prefix_key;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;

    /* Compression algorithm */
    int compression;
    flb_sds_t compression_str;
};

#endif
