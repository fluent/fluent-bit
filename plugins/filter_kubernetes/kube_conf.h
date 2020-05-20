/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_FILTER_KUBE_CONF_H
#define FLB_FILTER_KUBE_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_regex.h>

/*
 * Since this filter might get a high number of request per second,
 * we need to keep some cached data to perform filtering, e.g:
 *
 *  tag -> regex: pod name, container ID, container name, etc
 *
 * By default, we define a hash table for 256 entries.
 */
#define FLB_HASH_TABLE_SIZE 256

/*
 * When merging nested JSON strings from Docker logs, we need a temporal
 * buffer to perform the convertion. To optimize the process, we pre-allocate
 * a buffer for that purpose. The FLB_MERGE_BUF_SIZE defines the buffer size.
 *
 * Note: this is only the initial buffer size, it can grow depending on needs
 * for every incoming json-string.
 */
#define FLB_MERGE_BUF_SIZE  2048  /* 2KB */

/* Kubernetes API server info */
#define FLB_API_HOST  "kubernetes.default.svc"
#define FLB_API_PORT  443
#define FLB_API_TLS   FLB_TRUE

/*
 * Default expected Kubernetes tag prefix, this is used mostly when source
 * data comes from in_tail with custom tags like: kube.service.*
 */
#define FLB_KUBE_TAG_PREFIX "kube.var.log.containers."

struct kube_meta;

/* Filter context */
struct flb_kube {
    /* Configuration parameters */
    char *api_host;
    int api_port;
    int api_https;
    int use_journal;
    int labels;
    int annotations;
    int dummy_meta;
    int tls_debug;
    int tls_verify;
    flb_sds_t meta_preload_cache_dir;

    /* Configuration proposed through Annotations (boolean) */
    int k8s_logging_parser;   /* allow to process a suggested parser ? */
    int k8s_logging_exclude;  /* allowed to suggest to exclude logs ?  */

    /* HTTP Client Setup */
    size_t buffer_size;

    /* Merge Log feature */
    int merge_log;             /* old merge_json_log */

    struct flb_parser *merge_parser;

    /* Temporal buffer to unescape strings */
    size_t unesc_buf_size;
    size_t unesc_buf_len;
    char *unesc_buf;

    /*
     * Merge Log Trim: if merge_log is enabled, this flag allows to trim
     * the value and remove any trailing \n or \r.
     */
    int merge_log_trim;

    /* Log key, old merge_json_key (default 'log') */
    flb_sds_t merge_log_key;

    /* Keep original log key after successful parsing */
    int keep_log;

    /* API Server end point */
    char kube_url[1024];

    /* Kubernetes tag prefix */
    flb_sds_t kube_tag_prefix;

    /* Regex context to parse records */
    struct flb_regex *regex;
    struct flb_parser *parser;

    /* TLS CA certificate file */
    char *tls_ca_path;
    char *tls_ca_file;

    /* TLS virtual host (optional), set by configmap */
    flb_sds_t tls_vhost;

    /* Kubernetes Namespace */
    char *namespace;
    size_t namespace_len;

    /* POD Name where Fluent Bit is running */
    char *podname;
    size_t podname_len;

    /* Kubernetes Token from FLB_KUBE_TOKEN file */
    char *token_file;
    char *token;
    size_t token_len;

    /* Pre-formatted HTTP Authorization header value */
    char *auth;
    size_t auth_len;

    int dns_retries;
    int dns_wait_time;

    struct flb_tls tls;
    struct flb_config *config;
    struct flb_hash *hash_table;
    struct flb_upstream *upstream;
    struct flb_filter_instance *ins;
};

struct flb_kube *flb_kube_conf_create(struct flb_filter_instance *i,
                                      struct flb_config *config);
void flb_kube_conf_destroy(struct flb_kube *ctx);

#endif
