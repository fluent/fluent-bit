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

#include "kubernetes_events_conf.h"

#ifdef FLB_HAVE_SQLDB
#include "kubernetes_events_sql.h"


/* Open or create database required by tail plugin */
static struct flb_sqldb *flb_kubernetes_event_db_open(const char *path,
                                                      struct flb_input_instance *in,
                                                      struct k8s_events *ctx,
                                                      struct flb_config *config)
{
    int ret;
    char tmp[64];
    struct flb_sqldb *db;

    /* Open/create the database */
    db = flb_sqldb_open(path, in->name, config);
    if (!db) {
        return NULL;
    }

    /* Create table schema if it don't exists */
    ret = flb_sqldb_query(db, SQL_CREATE_KUBERNETES_EVENTS, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: could not create 'in_kubernetes_events' table");
        flb_sqldb_close(db);
        return NULL;
    }

    if (ctx->db_sync >= 0) {
        snprintf(tmp, sizeof(tmp) - 1, SQL_PRAGMA_SYNC,
                 ctx->db_sync);
        ret = flb_sqldb_query(db, tmp, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db could not set pragma 'sync'");
            flb_sqldb_close(db);
            return NULL;
        }
    }

    if (ctx->db_locking == FLB_TRUE) {
        ret = flb_sqldb_query(db, SQL_PRAGMA_LOCKING_MODE, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db: could not set pragma 'locking_mode'");
            flb_sqldb_close(db);
            return NULL;
        }
    }

    if (ctx->db_journal_mode) {
        snprintf(tmp, sizeof(tmp) - 1, SQL_PRAGMA_JOURNAL_MODE,
                 ctx->db_journal_mode);
        ret = flb_sqldb_query(db, tmp, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db could not set pragma 'journal_mode'");
            flb_sqldb_close(db);
            return NULL;
        }
    }

    return db;
}

static int flb_kubernetes_event_db_close(struct flb_sqldb *db)
{
    flb_sqldb_close(db);
    return 0;
}

#endif

static int network_init(struct k8s_events *ctx, struct flb_config *config)
{
    int io_type = FLB_IO_TCP;

    ctx->upstream = NULL;
    ctx->current_connection = NULL;
    ctx->streaming_client = NULL;

    if (ctx->api_https == FLB_TRUE) {
        if (!ctx->tls_ca_path && !ctx->tls_ca_file) {
            ctx->tls_ca_file = flb_strdup(K8S_EVENTS_KUBE_CA);
        }

        /* create a custom TLS context since we use user-defined certs */
        ctx->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                  ctx->tls_verify,
                                  ctx->tls_debug,
                                  ctx->tls_vhost,
                                  ctx->tls_ca_path,
                                  ctx->tls_ca_file,
                                  NULL, NULL, NULL);
        if (!ctx->tls) {
            return -1;
        }

        io_type = FLB_IO_TLS;
    }

    /* Create an Upstream context */
    ctx->upstream = flb_upstream_create(config,
                                        ctx->api_host,
                                        ctx->api_port,
                                        io_type,
                                        ctx->tls);
    if (!ctx->upstream) {
        flb_plg_error(ctx->ins, "network initialization failed");
        return -1;
    }

    return 0;
}

struct k8s_events *k8s_events_conf_create(struct flb_input_instance *ins)
{
    int off;
    int ret;
    const char *p;
    const char *url;
    const char *tmp;
    struct k8s_events *ctx = NULL;
    pthread_mutexattr_t attr;

    ctx = flb_calloc(1, sizeof(struct k8s_events));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    pthread_mutexattr_init(&attr);
    pthread_mutex_init(&ctx->lock, &attr);

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }
    flb_input_set_context(ins, ctx);

    ctx->encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->encoder) {
        flb_plg_error(ins, "could not initialize event encoder");
        k8s_events_conf_destroy(ctx);
        return NULL;
    }

    ctx->ra_resource_version = flb_ra_create(K8S_EVENTS_RA_RESOURCE_VERSION, FLB_TRUE);
    if (!ctx->ra_resource_version) {
        flb_plg_error(ctx->ins, "could not create record accessor for resource version");
        k8s_events_conf_destroy(ctx);
        return NULL;
    }

    /* Get Kubernetes API server */
    url = flb_input_get_property("kube_url", ins);
    if (!url) {
        ctx->api_host = flb_strdup(K8S_EVENTS_KUBE_API_HOST);
        ctx->api_port =  K8S_EVENTS_KUBE_API_PORT;
        ctx->api_https = FLB_TRUE;
    }
    else {
        tmp = url;

        /* Check the protocol */
        if (strncmp(tmp, "http://", 7) == 0) {
            off = 7;
            ctx->api_https = FLB_FALSE;
        }
        else if (strncmp(tmp, "https://", 8) == 0) {
            off = 8;
            ctx->api_https = FLB_TRUE;
        }
        else {
            k8s_events_conf_destroy(ctx);
            return NULL;
        }

        /* Get hostname and TCP port */
        p = url + off;
        tmp = strchr(p, ':');
        if (tmp) {
            ctx->api_host = flb_strndup(p, tmp - p);
            tmp++;
            ctx->api_port = atoi(tmp);
        }
        else {
            ctx->api_host = flb_strdup(p);
            ctx->api_port = K8S_EVENTS_KUBE_API_PORT;
        }
    }
    snprintf(ctx->kube_url, sizeof(ctx->kube_url) - 1,
             "%s://%s:%i",
             ctx->api_https ? "https" : "http",
             ctx->api_host, ctx->api_port);

    flb_plg_info(ctx->ins, "API server: %s", ctx->kube_url);

    /* network setup */
    ret = network_init(ctx, ins->config);
    if (ret == -1) {
        k8s_events_conf_destroy(ctx);
        return NULL;
    }

#ifdef FLB_HAVE_SQLDB
    /* Initialize database */
    tmp = flb_input_get_property("db", ins);
    if (tmp) {
        ctx->db = flb_kubernetes_event_db_open(tmp, ins, ctx, ins->config);
        if (!ctx->db) {
            flb_plg_error(ctx->ins, "could not open/create database");
            k8s_events_conf_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->db) {
        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_KUBERNETES_EVENT_EXISTS_BY_UID,
                                 -1,
                                 &ctx->stmt_get_kubernetes_event_exists_by_uid,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement: stmt_get_kubernetes_event_exists_by_uid");
            k8s_events_conf_destroy(ctx);
            return NULL;
        }

        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_INSERT_KUBERNETES_EVENTS,
                                 -1,
                                 &ctx->stmt_insert_kubernetes_event,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement: stmt_insert_kubernetes_event");
            k8s_events_conf_destroy(ctx);
            return NULL;
        }

        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_DELETE_OLD_KUBERNETES_EVENTS,
                                 -1,
                                 &ctx->stmt_delete_old_kubernetes_events,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement: stmt_delete_old_kubernetes_events");
            k8s_events_conf_destroy(ctx);
            return NULL;
        }
    }
#endif

    return ctx;
}

void k8s_events_conf_destroy(struct k8s_events *ctx)
{

    if (ctx->ra_resource_version) {
        flb_ra_destroy(ctx->ra_resource_version);
    }

    if(ctx->streaming_client) {
        flb_http_client_destroy(ctx->streaming_client);
    }

    if(ctx->current_connection) {
        flb_upstream_conn_release(ctx->current_connection);
    }

    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }

    if (ctx->encoder) {
        flb_log_event_encoder_destroy(ctx->encoder);
    }

    if (ctx->api_host) {
        flb_free(ctx->api_host);
    }
    if (ctx->token) {
        flb_free(ctx->token);
    }
    if (ctx->auth) {
        flb_free(ctx->auth);
    }

#ifdef FLB_HAVE_TLS
    if (ctx->tls) {
        flb_tls_destroy(ctx->tls);
    }
#endif

#ifdef FLB_HAVE_SQLDB
    if (ctx->db) {
        flb_kubernetes_event_db_close(ctx->db);
    }
#endif

    flb_free(ctx);
}
