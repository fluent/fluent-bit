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

#ifndef FLB_IN_KUBERNETES_EVENTS_H
#define FLB_IN_KUBERNETES_EVENTS_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_sqldb.h>

#define DEFAULT_INTERVAL_SEC "0"
#define DEFAULT_INTERVAL_NSEC "500000000"

/* Filter context */
struct k8s_events {
    int coll_id;
    int coll_cleanup_id;
    int interval_sec;             /* interval collection time (Second)     */
    int interval_nsec;            /* interval collection time (Nanosecond) */
    int retention_time;           /* retention time limit, default 1 hour */

    /* Configuration parameters */
    char *api_host;
    int api_port;
    int api_https;
    int tls_debug;
    int tls_verify;
    int kube_token_ttl;
    flb_sds_t namespace;

    /* API Server end point */
    char kube_url[1024];

    /* TLS CA certificate file */
    char *tls_ca_path;
    char *tls_ca_file;

    /* TLS virtual host (optional), set by configmap */
    flb_sds_t tls_vhost;

    /* Kubernetes Token from FLB_KUBE_TOKEN file */
    char *token_file;
    char *token;
    int token_ttl;
    size_t token_len;
    int token_created;

    /* Pre-formatted HTTP Authorization header value */
    char *auth;
    size_t auth_len;

    int dns_retries;
    int dns_wait_time;

    struct flb_tls *tls;

    struct flb_log_event_encoder *encoder;

    /* record accessor */
    struct flb_record_accessor *ra_resource_version;

    /* others */
    struct flb_config *config;
    struct flb_upstream *upstream;
    struct flb_input_instance *ins;

    /* limit for event queries */
    int limit_request;
    /* last highest seen resource_version */
    uint64_t last_resource_version;

#ifdef FLB_HAVE_SQLDB
    /* State database */
    struct flb_sqldb *db;
    int db_sync;
    int db_locking;
    flb_sds_t db_journal_mode;
    sqlite3_stmt *stmt_get_kubernetes_event_exists_by_uid;
    sqlite3_stmt *stmt_insert_kubernetes_event;
    sqlite3_stmt *stmt_delete_old_kubernetes_events;
#endif

    /* concurrency lock */
    pthread_mutex_t lock;
};

#endif
