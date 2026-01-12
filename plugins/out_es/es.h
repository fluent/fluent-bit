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

#ifndef FLB_OUT_ES_H
#define FLB_OUT_ES_H

#include <monkey/mk_core/mk_list.h>

#include "es_type.h"

#define FLB_ES_DEFAULT_HOST       "127.0.0.1"
#define FLB_ES_DEFAULT_PORT       9200
#define FLB_ES_DEFAULT_INDEX      "fluent-bit"
#define FLB_ES_DEFAULT_TYPE       "_doc"
#define FLB_ES_DEFAULT_PREFIX     "logstash"
#define FLB_ES_DEFAULT_TIME_FMT   "%Y.%m.%d"
#define FLB_ES_DEFAULT_TIME_KEY   "@timestamp"
#define FLB_ES_DEFAULT_TIME_KEYF  "%Y-%m-%dT%H:%M:%S"
#define FLB_ES_DEFAULT_TAG_KEY    "flb-key"
#define FLB_ES_DEFAULT_HTTP_MAX   "512k"
#define FLB_ES_DEFAULT_HTTPS_PORT 443

#define FLB_ES_STATUS_SUCCESS          (1 << 0)
#define FLB_ES_STATUS_IMCOMPLETE       (1 << 1)
#define FLB_ES_STATUS_ERROR_UNPACK     (1 << 2)
#define FLB_ES_STATUS_BAD_TYPE         (1 << 3)
#define FLB_ES_STATUS_INVAILD_ARGUMENT (1 << 4)
#define FLB_ES_STATUS_BAD_RESPONSE     (1 << 5)
#define FLB_ES_STATUS_DUPLICATES       (1 << 6)
#define FLB_ES_STATUS_ERROR            (1 << 7)

struct flb_upstream;
struct flb_upstream_ha;
struct flb_upstream_node;
struct flb_output_instance;

struct flb_elasticsearch_config {
    /* Elasticsearch index (database) and type (table) */
    struct flb_es_str index;
    struct flb_es_str type;
    int suppress_type_name;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;
    char *http_api_key;

    /* Elastic Cloud Auth */
    struct flb_es_str cloud_user;
    struct flb_es_str cloud_passwd;

    /* AWS Auth */
#ifdef FLB_HAVE_AWS
    int has_aws_auth;
    char *aws_region;
    char *aws_sts_endpoint;
    char *aws_profile;
    struct flb_es_aws_provider aws_provider;
    struct flb_es_aws_provider base_aws_provider;
    /* tls instances can't be re-used; aws provider requires a separate one */
    struct flb_es_tls aws_tls;
    struct flb_es_tls aws_sts_tls;
    char *aws_service_name;
    struct flb_es_slist aws_unsigned_headers;
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
    struct flb_es_sds_t logstash_prefix;
    struct flb_es_sds_t logstash_prefix_separator;

    /* prefix key */
    struct flb_es_sds_t logstash_prefix_key;

    /* date format */
    struct flb_es_sds_t logstash_dateformat;

    /* time key */
    struct flb_es_sds_t time_key;

    /* time key format */
    struct flb_es_sds_t time_key_format;

    /* time key nanoseconds */
    int time_key_nanos;

    /* write operation */
    struct flb_es_sds_t write_operation;
    /* write operation elasticsearch operation */
    const char *es_action;

    /* id_key */
    struct flb_es_sds_t id_key;
    struct flb_es_record_accessor ra_id_key;

    /* include_tag_key */
    int include_tag_key;
    struct flb_es_sds_t tag_key;

    /* Elasticsearch HTTP API */
    char uri[256];

    struct flb_es_record_accessor ra_prefix_key;

    /* Compression mode (gzip) */
    int compress_gzip;

    /* List entry data for flb_elasticsearch->configs list */
    struct mk_list _head;
};

struct flb_elasticsearch {
    /* if HA mode is enabled */
    int ha_mode;
    struct flb_upstream_ha *ha;

    /* Upstream handler and config context for single mode (no HA) */
    struct flb_upstream *u;
    struct mk_list configs;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

/**
 *  Get plugin configuration.
 *  In HA mode, the selected upstream node is also output.
 *  In HA mode, the returned plugin configuration matches the output upstream node.
 *
 *  @param ctx  Non-NULL plugin context.
 *  @param node Non-NULL output parameter for selected upstream node.
 *              `*node` is set to NULL if not in HA mode or
 *              there is no upstream node.
 *
 *  @return Configuration of plugin or NULL if error happened or
 *          there is no upstream node (in HA mode).
 */
struct flb_elasticsearch_config *flb_elasticsearch_target(
        struct flb_elasticsearch *ctx, struct flb_upstream_node **node);

#endif
