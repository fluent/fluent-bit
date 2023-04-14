/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_OUT_ES_H
#define FLB_OUT_ES_H

#define FLB_ES_DEFAULT_HOST       "127.0.0.1"
#define FLB_ES_DEFAULT_PORT       92000
#define FLB_ES_DEFAULT_INDEX      "fluent-bit"
#define FLB_ES_DEFAULT_TYPE       "_doc"
#define FLB_ES_DEFAULT_PREFIX     "logstash"
#define FLB_ES_DEFAULT_TIME_FMT   "%Y.%m.%d"
#define FLB_ES_DEFAULT_TIME_KEY   "@timestamp"
#define FLB_ES_DEFAULT_TIME_KEYF  "%Y-%m-%dT%H:%M:%S"
#define FLB_ES_DEFAULT_TAG_KEY    "flb-key"
#define FLB_ES_DEFAULT_HTTP_MAX   "512k"
#define FLB_ES_DEFAULT_HTTPS_PORT 443
#define FLB_ES_WRITE_OP_INDEX     "index"
#define FLB_ES_WRITE_OP_CREATE    "create"
#define FLB_ES_WRITE_OP_UPDATE    "update"
#define FLB_ES_WRITE_OP_UPSERT    "upsert"

struct flb_elasticsearch {
    /* Elasticsearch index (database) and type (table) */
    char *index;
    char *type;
    char suppress_type_name;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* Elastic Cloud Auth */
    char *cloud_user;
    char *cloud_passwd;

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

    /*
     * If enabled, replace field name dots with underscore, required for
     * Elasticsearch 2.0-2.3.
     */
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


    /* write operation */
    flb_sds_t write_operation;
    /* write operation elasticsearch operation */
    flb_sds_t es_action;

    /* id_key */
    flb_sds_t id_key;
    struct flb_record_accessor *ra_id_key;

    /* include_tag_key */
    int include_tag_key;
    flb_sds_t tag_key;

    /* Elasticsearch HTTP API */
    char uri[256];

    struct flb_record_accessor *ra_prefix_key;

    /* Compression mode (gzip) */
    int compress_gzip;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

#endif
