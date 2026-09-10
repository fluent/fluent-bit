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

#include <ctype.h>

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_conf.h"
#include "azure_logs_ingestion_batch.h"

#ifdef FLB_HAVE_METRICS
/* Keep the 200 KiB boundary explicit for the small-request percentage. */
static const double payload_size_buckets[] = {
    65536.0,
    131072.0,
    204800.0,
    262144.0,
    524288.0,
    786432.0,
    900000.0,
    1048576.0,
    2097152.0,
    4194304.0,
    8388608.0,
    16777216.0
};

static struct cmt_counter *create_counter(struct flb_az_li *ctx,
                                          const char *name, const char *help)
{
    return cmt_counter_create(ctx->ins->cmt, "fluentbit", "azure_logs_ingestion",
                              (char *) name, (char *) help,
                              2, (char *[]) {"name", "dcr_id"});
}

static struct cmt_gauge *create_gauge(struct flb_az_li *ctx,
                                      const char *name, const char *help)
{
    return cmt_gauge_create(ctx->ins->cmt, "fluentbit", "azure_logs_ingestion",
                            (char *) name, (char *) help,
                            2, (char *[]) {"name", "dcr_id"});
}

static void initialize_payload_size_metrics(struct flb_az_li *ctx)
{
    size_t bucket_count;
    struct cmt_histogram_buckets *buckets;

    bucket_count = sizeof(payload_size_buckets) / sizeof(payload_size_buckets[0]);
    buckets = cmt_histogram_buckets_create_size(
                    (double *) payload_size_buckets, bucket_count);
    if (buckets != NULL) {
        ctx->cmt_uncompressed_payload_size = cmt_histogram_create(
                    ctx->ins->cmt, "fluentbit", "azure_logs_ingestion",
                    "uncompressed_payload_size_bytes",
                    "Uncompressed request payload size in bytes.", buckets,
                    2, (char *[]) {"name", "dcr_id"});
        if (ctx->cmt_uncompressed_payload_size == NULL) {
            cmt_histogram_buckets_destroy(buckets);
        }
    }
    buckets = cmt_histogram_buckets_create_size(
                    (double *) payload_size_buckets, bucket_count);
    if (buckets != NULL) {
        ctx->cmt_http_payload_size = cmt_histogram_create(
                    ctx->ins->cmt, "fluentbit", "azure_logs_ingestion",
                    "http_payload_size_bytes", "HTTP request payload size in bytes.",
                    buckets, 2, (char *[]) {"name", "dcr_id"});
        if (ctx->cmt_http_payload_size == NULL) {
            cmt_histogram_buckets_destroy(buckets);
        }
    }

    ctx->cmt_admitted_chunks = create_counter(ctx, "admitted_chunks_total",
                                               "Chunks durably admitted locally.");
    ctx->cmt_admitted_records = create_counter(ctx, "admitted_records_total",
                                                "Records durably admitted locally.");
    ctx->cmt_admitted_bytes = create_counter(ctx, "admitted_bytes_total",
                                              "JSON bytes durably admitted locally.");
    ctx->cmt_delivered_chunks = create_counter(ctx, "delivered_chunks_total",
                                                "Chunks accepted by Azure.");
    ctx->cmt_delivered_records = create_counter(ctx, "delivered_records_total",
                                                 "Records accepted by Azure.");
    ctx->cmt_delivered_bytes = create_counter(ctx, "delivered_bytes_total",
                                               "JSON bytes accepted by Azure.");
    ctx->cmt_quarantined_chunks = create_counter(ctx, "quarantined_chunks_total",
                                                  "Chunks newly quarantined.");
    ctx->cmt_quarantined_records = create_counter(ctx, "quarantined_records_total",
                                                   "Records newly quarantined.");
    ctx->cmt_quota_rejections = create_counter(ctx, "quota_rejections_total",
                                                "Chunk admissions rejected by quota.");
    ctx->cmt_persistence_failures = create_counter(ctx, "persistence_failures_total",
                                                    "Local persistence failures.");
    ctx->cmt_degraded_recoveries = create_counter(ctx, "degraded_recoveries_total",
                                                   "Recoveries from degraded state.");
    ctx->cmt_queued_chunks = create_gauge(ctx, "queued_chunks", "Queued chunks.");
    ctx->cmt_queued_records = create_gauge(ctx, "queued_records", "Queued records.");
    ctx->cmt_queued_bytes = create_gauge(ctx, "queued_bytes", "Queued JSON bytes.");
    ctx->cmt_quarantined_chunks_current = create_gauge(
                    ctx, "quarantined_chunks", "Currently quarantined chunks.");
    ctx->cmt_quarantined_bytes = create_gauge(
                    ctx, "quarantined_bytes", "Currently quarantined JSON bytes.");
    ctx->cmt_quota_used_bytes = create_gauge(
                    ctx, "quota_used_bytes", "Logical spool quota used in bytes.");
    ctx->cmt_quota_limit_bytes = create_gauge(
                    ctx, "quota_limit_bytes", "Configured spool quota in bytes.");
    ctx->cmt_oldest_queued_age = create_gauge(
                    ctx, "oldest_queued_age_seconds", "Age of oldest queued chunk.");
    ctx->cmt_uploader_up = create_gauge(ctx, "uploader_up", "Uploader health state.");
    ctx->cmt_uploader_consecutive_failures = create_gauge(
                    ctx, "uploader_consecutive_failures", "Consecutive local failures.");
    ctx->cmt_uploader_last_success = create_gauge(
                    ctx, "uploader_last_success_timestamp_seconds",
                    "Unix timestamp of last durable Azure success.");

    if (ctx->cmt_uncompressed_payload_size == NULL ||
        ctx->cmt_http_payload_size == NULL) {
        flb_plg_warn(ctx->ins, "payload size metrics are unavailable");
    }
}
#endif

static int validate_buffer_key(const char *key)
{
    const unsigned char *cursor;

    if (key == NULL || key[0] == '\0' ||
        strcmp(key, ".") == 0 || strcmp(key, "..") == 0) {
        return -1;
    }

    cursor = (const unsigned char *) key;
    while (*cursor != '\0') {
        if (!isalnum(*cursor) && *cursor != '-' && *cursor != '_' && *cursor != '.') {
            return -1;
        }
        cursor++;
    }
    return 0;
}

static int validate_auth_url_override(struct flb_output_instance *ins,
                                      flb_sds_t auth_url_override)
{
    int ret;
    int result;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;

    result = -1;

    ret = flb_utils_url_split(auth_url_override, &protocol, &host, &port, &uri);
    if (ret == -1 || protocol == NULL || host == NULL) {
        flb_plg_error(ins, "property 'auth_url' has an invalid URL");
        goto cleanup;
    }

    if (strcasecmp(protocol, "https") == 0) {
        result = 0;
        goto cleanup;
    }

    if (strcasecmp(protocol, "http") != 0) {
        flb_plg_error(ins, "property 'auth_url' must use http or https");
        goto cleanup;
    }

    if (strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0) {
        result = 0;
        goto cleanup;
    }

    flb_plg_error(ins,
                  "property 'auth_url' must use https or an explicit loopback "
                  "http endpoint");

cleanup:
    if (protocol != NULL) {
        flb_free(protocol);
    }
    if (host != NULL) {
        flb_free(host);
    }
    if (port != NULL) {
        flb_free(port);
    }
    if (uri != NULL) {
        flb_free(uri);
    }

    return result;
}

struct flb_az_li* flb_az_li_ctx_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    struct flb_az_li *ctx;
    struct flb_oauth2_config oauth2_config;
    (void) ins;
    (void) config;

    /* Allocate a new context object for this output instance */
    ctx = flb_calloc(1, sizeof(struct flb_az_li));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Set the conext in output_instance so that we can retrieve it later */
    ctx->ins = ins;
    ctx->config = config;
    /* Set context */
    flb_output_set_context(ins, ctx);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        return NULL;
    }

    /* config: 'client_id' */
    if (!ctx->client_id) {
        flb_plg_error(ins, "property 'client_id' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'tenant_id' */
    if (!ctx->tenant_id && !ctx->auth_url_override) {
        flb_plg_error(ins, "property 'tenant_id' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'client_secret' */
    if (!ctx->client_secret) {
        flb_plg_error(ins, "property 'client_secret' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'dce_url' */
    if (!ctx->dce_url) {
        flb_plg_error(ins, "property 'dce_url' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'dcr_id' */
    if (!ctx->dcr_id) {
        flb_plg_error(ins, "property 'dcr_id' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    /* config: 'table_name' */
    if (!ctx->table_name) {
        flb_plg_error(ins, "property 'table_name' is not defined");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }

    if (ctx->buffering_enabled == FLB_TRUE) {
#ifndef FLB_HAVE_SQLDB
        flb_plg_error(ins,
                      "buffering_enabled requires a build with FLB_SQLDB=On");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
#endif
#ifdef _WIN32
        flb_plg_error(ins, "buffering_enabled is not supported on Windows because "
                           "cross-process spool locking is unavailable");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
#endif
        if (ctx->compress_enabled != FLB_TRUE) {
            flb_plg_error(ins, "buffering_enabled requires compress=true");
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        if (ins->retry_limit != FLB_OUT_RETRY_UNLIMITED) {
            flb_plg_error(ins,
                          "buffering_enabled requires retry_limit=no_limits so "
                          "pre-ownership retries cannot be dropped");
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        if (ctx->batch_target_size == 0 ||
            ctx->batch_target_size > FLB_AZ_LI_MAX_REQUEST_SIZE) {
            flb_plg_error(ins,
                          "batch_target_size must be between 1 and %d bytes",
                          FLB_AZ_LI_MAX_REQUEST_SIZE);
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        if (ctx->batch_timeout <= 0 || ctx->batch_max_uncompressed_size == 0) {
            flb_plg_error(ins, "batch timeout and uncompressed size must be positive");
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        if (ctx->buffer_dir_limit_size == 0) {
            flb_plg_error(ins,
                          "buffer_dir_limit_size is required when buffering is enabled");
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        if (ctx->buffer_dir_limit_size < FLB_AZ_LI_MIN_BUFFER_SIZE) {
            flb_plg_error(ins,
                          "buffer_dir_limit_size must be at least %d bytes to leave "
                          "request construction headroom",
                          FLB_AZ_LI_MIN_BUFFER_SIZE);
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        if (ctx->upload_retry_limit < 0 || ctx->upload_retry_base <= 0 ||
            ctx->buffer_receipt_ttl <= 0 || ctx->http_timeout <= 0) {
            flb_plg_error(ins, "retry, receipt TTL and HTTP timeout values are invalid");
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        if (ctx->buffer_key == NULL) {
            ctx->buffer_key = flb_sds_create_size(flb_sds_len(ctx->dcr_id) +
                                                  flb_sds_len(ctx->table_name) + 2);
            if (ctx->buffer_key == NULL) {
                flb_az_li_ctx_destroy(ctx);
                return NULL;
            }
            flb_sds_snprintf(&ctx->buffer_key, flb_sds_alloc(ctx->buffer_key),
                             "%s-%s", ctx->dcr_id, ctx->table_name);
            ctx->buffer_key_owned = FLB_TRUE;
        }
        if (validate_buffer_key(ctx->buffer_key) == -1) {
            flb_plg_error(ins,
                          "buffer_key must be a non-special path component containing "
                          "only letters, digits, '.', '_' and '-'");
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
    }

    if (ctx->auth_url_override) {
        ret = validate_auth_url_override(ins, ctx->auth_url_override);
        if (ret == -1) {
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }

        ctx->auth_url = flb_sds_create(ctx->auth_url_override);
        if (!ctx->auth_url) {
            flb_errno();
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
    }
    else {
        /* Allocate and set auth url */
        ctx->auth_url = flb_sds_create_size(sizeof(FLB_AZ_LI_AUTH_URL_TMPLT) - 1 +
                                            flb_sds_len(ctx->tenant_id));
        if (!ctx->auth_url) {
            flb_errno();
            flb_az_li_ctx_destroy(ctx);
            return NULL;
        }
        flb_sds_snprintf(&ctx->auth_url, flb_sds_alloc(ctx->auth_url),
                        FLB_AZ_LI_AUTH_URL_TMPLT, ctx->tenant_id);
    }

    /* Allocate and set dce full url */
    ctx->dce_u_url = flb_sds_create_size(sizeof(FLB_AZ_LI_DCE_URL_TMPLT) - 1 +
                                        flb_sds_len(ctx->dce_url) +
                                        flb_sds_len(ctx->dcr_id) +
                                        flb_sds_len(ctx->table_name));
    if (!ctx->dce_u_url) {
        flb_errno();
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    flb_sds_snprintf(&ctx->dce_u_url, flb_sds_alloc(ctx->dce_u_url),
                    FLB_AZ_LI_DCE_URL_TMPLT, ctx->dce_url, 
                    ctx->dcr_id, ctx->table_name);

#ifdef FLB_HAVE_METRICS
    ret = pthread_mutex_init(&ctx->payload_metrics_mutex, NULL);
    if (ret == 0) {
        ctx->payload_metrics_mutex_initialized = FLB_TRUE;
        initialize_payload_size_metrics(ctx);
    }
    else {
        flb_plg_warn(ins, "payload and lifecycle metrics are unavailable");
    }
#endif

    /* Initialize the auth mutex */
    ret = pthread_mutex_init(&ctx->token_mutex, NULL);
    if (ret != 0) {
        flb_plg_error(ins, "could not initialize token mutex");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    ctx->token_mutex_initialized = FLB_TRUE;

    /* Create oauth2 context */
    if (ctx->buffering_enabled == FLB_TRUE) {
        memset(&oauth2_config, 0, sizeof(oauth2_config));
        oauth2_config.enabled = FLB_TRUE;
        oauth2_config.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
        oauth2_config.token_url = ctx->auth_url;
        oauth2_config.timeout = ctx->http_timeout;
        oauth2_config.connect_timeout = ctx->http_timeout;
        ctx->u_auth = flb_oauth2_create_from_config(config, &oauth2_config);
    }
    else {
        ctx->u_auth = flb_oauth2_create(config, ctx->auth_url,
                                        FLB_AZ_LI_TOKEN_TIMEOUT);
    }
    if (!ctx->u_auth) {
        flb_plg_error(ins, "cannot create oauth2 context");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }

    /* Create upstream context for Log Ingsetion endpoint */
    ctx->u_dce = flb_upstream_create_url(config, ctx->dce_url,
                                        FLB_AZ_LI_TLS_MODE, ins->tls);
    if (!ctx->u_dce) {
        flb_plg_error(ins, "upstream creation failed");
        flb_az_li_ctx_destroy(ctx);
        return NULL;
    }
    flb_output_upstream_set(ctx->u_dce, ins);
    if (ctx->buffering_enabled == FLB_TRUE) {
        ctx->u_dce->base.net.connect_timeout = ctx->http_timeout;
    }

    flb_plg_info(ins, "dce_url='%s', dcr='%s', table='%s', stream='Custom-%s'",
                ctx->dce_url, ctx->dcr_id, ctx->table_name, ctx->table_name);

    return ctx;
}

/* Free the context and created memory */
int flb_az_li_ctx_destroy(struct flb_az_li *ctx)
{
    if (!ctx) {
        return -1;
    }

#ifdef FLB_HAVE_SQLDB
    if (ctx->batch) {
        az_li_batch_destroy(ctx);
    }
#endif

    if (ctx->auth_url) {
        flb_sds_destroy(ctx->auth_url);
    }

    if (ctx->dce_u_url) {
        flb_sds_destroy(ctx->dce_u_url);
    }

    if (ctx->u_auth) {
        flb_oauth2_destroy(ctx->u_auth);
    }

    if (ctx->u_dce) {
        flb_upstream_destroy(ctx->u_dce);
    }
    if (ctx->token_mutex_initialized == FLB_TRUE) {
        pthread_mutex_destroy(&ctx->token_mutex);
    }
    if (ctx->buffer_key && ctx->buffer_key_owned == FLB_TRUE) {
        flb_sds_destroy(ctx->buffer_key);
    }
#ifdef FLB_HAVE_METRICS
    if (ctx->payload_metrics_mutex_initialized == FLB_TRUE) {
        pthread_mutex_destroy(&ctx->payload_metrics_mutex);
    }
#endif
    flb_free(ctx);

    return 0;
}
