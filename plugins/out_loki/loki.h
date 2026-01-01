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

#ifndef FLB_OUT_LOKI_H
#define FLB_OUT_LOKI_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_hash_table.h>
#include <cfl/cfl_list.h>

#define FLB_LOKI_CT              "Content-Type"
#define FLB_LOKI_CT_JSON         "application/json"
#define FLB_LOKI_URI             "/loki/api/v1/push"
#define FLB_LOKI_HOST            "127.0.0.1"
#define FLB_LOKI_PORT            3100
#define FLB_LOKI_HEADER_SCOPE    "X-Scope-OrgID"

#define FLB_LOKI_KV_STR    0     /* sds string */
#define FLB_LOKI_KV_RA     1     /* record accessor */
#define FLB_LOKI_KV_K8S    2     /* kubernetes label */

/* Output line format */
#define FLB_LOKI_FMT_JSON  0
#define FLB_LOKI_FMT_KV    1

/* Drop single key */
#define FLB_LOKI_DROP_SINGLE_KEY_OFF (((uint64_t) 1) << 0)
#define FLB_LOKI_DROP_SINGLE_KEY_ON  (((uint64_t) 1) << 1)
#define FLB_LOKI_DROP_SINGLE_KEY_RAW (((uint64_t) 1) << 2)

struct flb_loki_kv {
    int val_type;                       /* FLB_LOKI_KV_STR or FLB_LOKI_KV_RA */
    flb_sds_t key;                      /* string key */
    flb_sds_t str_val;                  /* string value */
    flb_sds_t key_normalized;           /* normalized key name when using ra */
    struct flb_record_accessor *ra_key; /* record accessor key context */
    struct flb_record_accessor *ra_val; /* record accessor value context */
    struct mk_list _head;               /* link to flb_loki->labels_list */
};

struct flb_loki {
    /* Public configuration properties */
    int auto_kubernetes_labels;

    flb_sds_t drop_single_key;
    flb_sds_t uri;
    flb_sds_t line_format;
    flb_sds_t tenant_id;
    flb_sds_t tenant_id_key_config;
    int compress_gzip;

    /* HTTP Auth */
    flb_sds_t http_user;
    flb_sds_t http_passwd;

    /* Bearer Token Auth */
    flb_sds_t bearer_token;

    /* Labels */
    struct mk_list *labels;
    struct mk_list *label_keys;
    struct mk_list *structured_metadata;
    struct mk_list *structured_metadata_map_keys;
    struct mk_list *remove_keys;

    flb_sds_t label_map_path;

    /* Private */
    int tcp_port;
    char *tcp_host;
    int out_line_format;
    int out_drop_single_key;
    int ra_used;                           /* number of record accessor label keys */
    struct flb_record_accessor *ra_k8s;              /* kubernetes record accessor */
    struct mk_list labels_list;                       /* list of flb_loki_kv nodes */
    struct mk_list structured_metadata_list;          /* list of flb_loki_kv nodes */
    struct mk_list structured_metadata_map_keys_list; /* list of flb_loki_kv nodes */
    struct mk_list remove_keys_derived;              /* remove_keys with label RAs */
    struct flb_mp_accessor *remove_mpa;      /* remove_keys multi-pattern accessor */
    struct flb_record_accessor *ra_tenant_id_key;         /* dynamic tenant id key */

    struct cfl_list dynamic_tenant_list;
    pthread_mutex_t dynamic_tenant_list_lock;

    struct cfl_list remove_mpa_list;
    pthread_mutex_t remove_mpa_list_lock;

    /* Upstream Context */
    struct flb_upstream *u;

    /* Plugin instance */
    struct flb_output_instance *ins;

    /* Arbitrary HTTP headers */
    struct mk_list *headers;

    /* Response buffer size */
    size_t http_buffer_max_size;

};

#endif
