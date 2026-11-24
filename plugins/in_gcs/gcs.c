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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_str.h>

#include "gcs.h"

/*
 * Restart semantics (at-least-once): the database only records an object once it has
 * been completely emitted. If Fluent Bit stops in the middle of an object, the whole
 * object is emitted again on the next run.
 */

static int gcs_is_disabled_value(const char *value)
{
    return strcasecmp(value, "false") == 0 || strcasecmp(value, "off") == 0 ||
           strcasecmp(value, "none") == 0;
}

static int gcs_parse_time_format(const char *name)
{
    if (strcasecmp(name, "auto") == 0) {
        return FLB_GCS_TIME_AUTO;
    }
    if (strcasecmp(name, "iso8601") == 0) {
        return FLB_GCS_TIME_ISO8601;
    }
    if (strcasecmp(name, "java_sql_timestamp") == 0) {
        return FLB_GCS_TIME_JAVA_SQL;
    }
    if (strcasecmp(name, "double") == 0) {
        return FLB_GCS_TIME_DOUBLE;
    }
    if (strcasecmp(name, "epoch") == 0) {
        return FLB_GCS_TIME_EPOCH;
    }
    if (strcasecmp(name, "epoch_ms") == 0) {
        return FLB_GCS_TIME_EPOCH_MS;
    }
    return -1;
}

static void gcs_ctx_destroy(struct flb_in_gcs *ctx)
{
    if (!ctx) {
        return;
    }

    in_gcs_items_destroy(ctx);
    in_gcs_current_clear(ctx);
    in_gcs_db_close(ctx);

    if (ctx->encoder) {
        flb_log_event_encoder_destroy(ctx->encoder);
    }
    if (ctx->tag_regex) {
        flb_regex_destroy(ctx->tag_regex);
    }
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    if (ctx->auth) {
        flb_gcp_auth_destroy(ctx->auth);
    }
    if (ctx->tls) {
        flb_tls_destroy(ctx->tls);
    }
    if (ctx->page_token) {
        flb_sds_destroy(ctx->page_token);
    }
    if (ctx->host) {
        flb_sds_destroy(ctx->host);
    }
    if (ctx->base_path) {
        flb_sds_destroy(ctx->base_path);
    }
    flb_free(ctx);
}

/* Split 'endpoint' into host, port and optional base path, and create the upstream */
static int gcs_network_init(struct flb_in_gcs *ctx)
{
    int ret;
    int io_flags = FLB_IO_TCP;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    size_t len;
    struct flb_tls *tls = NULL;

    ret = flb_utils_url_split(ctx->endpoint, &protocol, &host, &port, &uri);
    if (ret == -1 || !protocol || !host) {
        flb_plg_error(ctx->ins, "invalid 'endpoint' '%s'", ctx->endpoint);
        ret = -1;
        goto out;
    }

    if (strcasecmp(protocol, "https") == 0) {
        io_flags = FLB_IO_TLS;
        ctx->port = 443;
    }
    else if (strcasecmp(protocol, "http") == 0) {
        ctx->port = 80;
    }
    else {
        flb_plg_error(ctx->ins, "unsupported scheme in 'endpoint' '%s' "
                      "(use http:// or https://)", ctx->endpoint);
        ret = -1;
        goto out;
    }

    if (port) {
        ctx->port = atoi(port);
        if (ctx->port <= 0) {
            flb_plg_error(ctx->ins, "invalid port in 'endpoint' '%s'", ctx->endpoint);
            ret = -1;
            goto out;
        }
    }

    ctx->host = flb_sds_create(host);
    if (!ctx->host) {
        ret = -1;
        goto out;
    }

    /* optional base path (emulators behind a prefix), without the trailing slash */
    ctx->base_path = flb_sds_create("");
    if (!ctx->base_path) {
        ret = -1;
        goto out;
    }
    if (uri && strcmp(uri, "/") != 0) {
        len = strlen(uri);
        while (len > 0 && uri[len - 1] == '/') {
            len--;
        }
        flb_sds_destroy(ctx->base_path);
        ctx->base_path = flb_sds_create_len(uri, len);
        if (!ctx->base_path) {
            ret = -1;
            goto out;
        }
    }

    if (io_flags == FLB_IO_TLS) {
        /*
         * Inputs only get a TLS context when 'tls on' is set, but the default endpoint
         * is https: create a private context when the instance does not have one.
         */
        tls = ctx->ins->tls;
        if (!tls) {
            ctx->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                      ctx->ins->tls_verify,
                                      ctx->ins->tls_debug,
                                      ctx->ins->tls_vhost,
                                      ctx->ins->tls_ca_path,
                                      ctx->ins->tls_ca_file,
                                      ctx->ins->tls_crt_file,
                                      ctx->ins->tls_key_file,
                                      ctx->ins->tls_key_passwd);
            if (!ctx->tls) {
                flb_plg_error(ctx->ins, "could not create the TLS context");
                ret = -1;
                goto out;
            }
            flb_tls_set_verify_hostname(ctx->tls, ctx->ins->tls_verify_hostname);
            tls = ctx->tls;
        }
    }

    if (ctx->ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    ctx->upstream = flb_upstream_create(ctx->config, ctx->host, ctx->port, io_flags, tls);
    if (!ctx->upstream) {
        flb_plg_error(ctx->ins, "could not create the upstream for '%s'", ctx->endpoint);
        ret = -1;
        goto out;
    }

    /* apply net.* properties and thread safety */
    flb_input_upstream_set(ctx->upstream, ctx->ins);

    /* all requests are blocking calls made from the collector, outside of a coroutine */
    flb_stream_disable_async_mode(&ctx->upstream->base);
    ret = 0;

out:
    flb_free(protocol);
    flb_free(host);
    flb_free(port);
    flb_free(uri);
    return ret;
}

static int gcs_auth_init(struct flb_in_gcs *ctx)
{
    struct flb_gcp_auth_config auth_cfg;
    struct flb_input_instance *ins = ctx->ins;

    memset(&auth_cfg, 0, sizeof(auth_cfg));
    auth_cfg.config = ctx->config;
    auth_cfg.scope = FLB_GCP_SCOPE_STORAGE_READ_ONLY;
    auth_cfg.log_name = flb_input_name(ins);
    auth_cfg.credentials_file = ctx->credentials_file;
    auth_cfg.metadata_server = ctx->metadata_server;
    auth_cfg.identity_federation = ctx->has_identity_federation;
    auth_cfg.project_number = ctx->project_number;
    auth_cfg.pool_id = ctx->pool_id;
    auth_cfg.provider_id = ctx->provider_id;
    auth_cfg.identity_token_file = ctx->identity_token_file;
    auth_cfg.google_service_account = ctx->google_service_account;
    auth_cfg.subject_token_type = ctx->subject_token_type;
    auth_cfg.tls_verify = ins->tls_verify;
    auth_cfg.tls_debug = ins->tls_debug;
    auth_cfg.tls_verify_hostname = ins->tls_verify_hostname;
    auth_cfg.ipv6 = ins->host.ipv6;
    auth_cfg.tls_vhost = ins->tls_vhost;
    auth_cfg.tls_ca_path = ins->tls_ca_path;
    auth_cfg.tls_ca_file = ins->tls_ca_file;
    auth_cfg.tls_crt_file = ins->tls_crt_file;
    auth_cfg.tls_key_file = ins->tls_key_file;
    auth_cfg.tls_key_passwd = ins->tls_key_passwd;

    ctx->auth = flb_gcp_auth_create(&auth_cfg);
    return ctx->auth ? 0 : -1;
}

/* Validate the options that the config map cannot check */
static int gcs_validate_config(struct flb_in_gcs *ctx)
{
    int ret;

    if (!ctx->bucket || flb_sds_len(ctx->bucket) == 0) {
        flb_plg_error(ctx->ins, "'bucket' is required");
        return -1;
    }
    if (ctx->batch_size <= 0) {
        flb_plg_error(ctx->ins, "'batch_size' must be greater than zero");
        return -1;
    }
    if (ctx->page_size <= 0) {
        flb_plg_error(ctx->ins, "'page_size' must be greater than zero");
        return -1;
    }
    if (ctx->max_object_size == 0) {
        flb_plg_error(ctx->ins, "'max_object_size' must be greater than zero");
        return -1;
    }
    if (ctx->retry_limit < 0) {
        flb_plg_error(ctx->ins, "'retry_limit' cannot be negative");
        return -1;
    }

    if (strcasecmp(ctx->compression_name, "auto") == 0) {
        ctx->compression = FLB_GCS_COMPRESSION_AUTO;
    }
    else if (strcasecmp(ctx->compression_name, "none") == 0) {
        ctx->compression = FLB_GCS_COMPRESSION_NONE;
    }
    else if (strcasecmp(ctx->compression_name, "gzip") == 0) {
        ctx->compression = FLB_GCS_COMPRESSION_GZIP;
    }
    else {
        flb_plg_error(ctx->ins, "invalid 'compression' '%s' (auto, none or gzip)",
                      ctx->compression_name);
        return -1;
    }

    ret = gcs_parse_time_format(ctx->time_format_name);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "invalid 'time_format' '%s' (auto, iso8601, "
                      "java_sql_timestamp, double, epoch or epoch_ms)",
                      ctx->time_format_name);
        return -1;
    }
    ctx->time_format = ret;

    ctx->time_key_enabled = FLB_FALSE;
    if (ctx->time_key && flb_sds_len(ctx->time_key) > 0 &&
        gcs_is_disabled_value(ctx->time_key) == FLB_FALSE) {
        ctx->time_key_enabled = FLB_TRUE;
    }

    if (ctx->parser_name) {
        ctx->parser = flb_parser_get(ctx->parser_name, ctx->config);
        if (!ctx->parser) {
            flb_plg_error(ctx->ins, "parser '%s' not found", ctx->parser_name);
            return -1;
        }
    }

    if (ctx->tag_regex_pattern) {
        ctx->tag_regex = flb_regex_create(ctx->tag_regex_pattern);
        if (!ctx->tag_regex) {
            flb_plg_error(ctx->ins, "invalid 'tag_regex' '%s'", ctx->tag_regex_pattern);
            return -1;
        }
    }

    return 0;
}

static void gcs_complete(struct flb_in_gcs *ctx)
{
    const char *result = "completed";

    ctx->state = FLB_GCS_STATE_DONE;
    ctx->done = FLB_TRUE;

    if (ctx->failed == FLB_TRUE) {
        result = "failed";
    }
    else if (ctx->objects_failed > 0) {
        result = "completed with errors";
    }

    flb_plg_info(ctx->ins, "rehydration %s: objects processed=%" PRIu64 " skipped=%" PRIu64
                 " failed=%" PRIu64 ", records emitted=%" PRIu64,
                 result,
                 ctx->objects_processed, ctx->objects_skipped, ctx->objects_failed,
                 ctx->records_emitted);

    flb_input_collector_pause(ctx->coll_id, ctx->ins);

    if (ctx->exit_on_complete == FLB_TRUE) {
        /* objects skipped because of errors (not 404s) also fail the run */
        if (ctx->failed == FLB_TRUE || ctx->objects_failed > 0) {
            flb_engine_exit_status(ctx->config, 1);
        }
        else {
            flb_engine_exit(ctx->config);
        }
    }
}

static void gcs_fail_run(struct flb_in_gcs *ctx, const char *what)
{
    flb_plg_error(ctx->ins, "%s: %s", what, ctx->last_error);
    ctx->failed = FLB_TRUE;
    gcs_complete(ctx);
}

/* a request finished (successfully or not): the next one starts with a clean slate */
static void gcs_reset_request_state(struct flb_in_gcs *ctx)
{
    ctx->attempts = 0;
    ctx->auth_retried = FLB_FALSE;
}

/*
 * Common handling of a failed request. Returns FLB_TRUE if the same request must be
 * repeated on a later tick; FLB_FALSE if the caller has to give up (run failed or
 * the object has to be skipped, depending on 'result').
 */
static int gcs_should_retry(struct flb_in_gcs *ctx, int result, const char *what)
{
    if (result == FLB_GCS_REQ_UNAUTHORIZED) {
        if (ctx->auth_retried == FLB_FALSE) {
            /* a single retry with a fresh token, it does not use 'retry_limit' */
            ctx->auth_retried = FLB_TRUE;
            flb_plg_warn(ctx->ins, "%s: unauthorized, refreshing the token", what);
            flb_gcp_auth_invalidate_token(ctx->auth);
            return FLB_TRUE;
        }
        return FLB_FALSE;
    }

    if (result == FLB_GCS_REQ_TRANSIENT) {
        ctx->attempts++;
        if (ctx->attempts <= ctx->retry_limit) {
            flb_plg_warn(ctx->ins, "%s: temporary error (%s), retry %d/%d", what,
                         ctx->last_error, ctx->attempts, ctx->retry_limit);
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static void gcs_skip_current(struct flb_in_gcs *ctx, int failed)
{
    if (failed == FLB_TRUE) {
        ctx->objects_failed++;
    }
    else {
        ctx->objects_skipped++;
    }
    in_gcs_current_clear(ctx);
    gcs_reset_request_state(ctx);
    ctx->encode_failures = 0;
    ctx->state = FLB_GCS_STATE_NEXT;
}

static void gcs_tick_list(struct flb_in_gcs *ctx)
{
    int ret;

    ret = in_gcs_list_page(ctx);
    if (ret == FLB_GCS_REQ_OK) {
        gcs_reset_request_state(ctx);
        ctx->state = FLB_GCS_STATE_NEXT;
        return;
    }

    if (gcs_should_retry(ctx, ret, "listing") == FLB_TRUE) {
        return;
    }
    gcs_fail_run(ctx, "listing failed");
}

static void gcs_tick_next(struct flb_in_gcs *ctx)
{
    int i;
    int ret;
    struct gcs_item *item;

    for (i = 0; i < FLB_GCS_SKIP_PER_TICK; i++) {
        if (ctx->items_index >= ctx->items_count) {
            in_gcs_items_destroy(ctx);
            if (ctx->has_more_pages == FLB_TRUE) {
                ctx->state = FLB_GCS_STATE_LIST;
            }
            else {
                gcs_complete(ctx);
            }
            return;
        }

        item = &ctx->items[ctx->items_index++];
        if (flb_sds_len(item->name) == 0 ||
            (item->name[flb_sds_len(item->name) - 1] == '/' && item->size == 0)) {
            /* folder placeholder: an empty object whose name ends with a slash */
            continue;
        }

        ret = in_gcs_db_has_object(ctx, item->name, item->generation);
        if (ret == FLB_TRUE) {
            flb_plg_debug(ctx->ins, "skipping '%s' (generation %s): already processed",
                          item->name, item->generation);
            ctx->objects_skipped++;
            continue;
        }

        if (item->size > ctx->max_object_size) {
            flb_plg_error(ctx->ins, "skipping '%s': size %" PRIu64 " exceeds "
                          "'max_object_size' (%zu)", item->name, item->size,
                          ctx->max_object_size);
            ctx->objects_skipped++;
            continue;
        }

        /* take ownership of the strings of the item */
        ctx->current.name = item->name;
        ctx->current.generation = item->generation;
        ctx->current.size = item->size;
        item->name = NULL;
        item->generation = NULL;
        ctx->has_current = FLB_TRUE;
        ctx->state = FLB_GCS_STATE_DOWNLOAD;
        return;
    }
}

static void gcs_tick_download(struct flb_in_gcs *ctx)
{
    int ret;

    ret = in_gcs_download_object(ctx);
    if (ret == FLB_GCS_REQ_OK) {
        gcs_reset_request_state(ctx);
        ctx->state = FLB_GCS_STATE_EMIT;
        return;
    }

    if (gcs_should_retry(ctx, ret, "download") == FLB_TRUE) {
        return;
    }

    if (ret == FLB_GCS_REQ_FORBIDDEN || ret == FLB_GCS_REQ_UNAUTHORIZED) {
        gcs_fail_run(ctx, "download failed");
        return;
    }

    if (ret == FLB_GCS_REQ_NOT_FOUND) {
        flb_plg_warn(ctx->ins, "object '%s' not found (deleted after listing?), skipping",
                     ctx->current.name);
        gcs_skip_current(ctx, FLB_FALSE);
        return;
    }

    flb_plg_error(ctx->ins, "skipping object '%s': %s", ctx->current.name, ctx->last_error);
    gcs_skip_current(ctx, FLB_TRUE);
}

static void gcs_tick_emit(struct flb_in_gcs *ctx)
{
    int ret;

    if (flb_input_buf_paused(ctx->ins) == FLB_TRUE) {
        return;
    }

    ret = in_gcs_emit_batch(ctx);
    if (ret == FLB_GCS_EMIT_APPEND_FAILED) {
        /* backpressure: the same batch is tried again, as long as it takes */
        return;
    }
    if (ret == FLB_GCS_EMIT_ENCODE_FAILED) {
        ctx->encode_failures++;
        if (ctx->encode_failures <= ctx->retry_limit) {
            flb_plg_warn(ctx->ins, "encoding failed for '%s', retry %d/%d",
                         ctx->current.name, ctx->encode_failures, ctx->retry_limit);
            return;
        }

        /*
         * Give up on the object without recording it in the db. Records of earlier
         * batches were already ingested and stay (at-least-once).
         */
        flb_plg_error(ctx->ins, "skipping object '%s': its records could not be encoded",
                      ctx->current.name);
        gcs_skip_current(ctx, FLB_TRUE);
        return;
    }
    ctx->encode_failures = 0;

    if (ctx->buf_off >= ctx->buf_len) {
        /*
         * The object is recorded once all its records were handed to the engine. This
         * input runs in its own thread, so the records are queued in the input ring
         * buffer and stored by the main thread shortly after. The db protects against
         * restarts and interruptions of the plugin's own processing (an unfinished
         * object is read again in full), but a hard crash can still lose records that
         * the engine had buffered and not yet delivered, as with any other input.
         */
        in_gcs_db_record_object(ctx, ctx->current.name, ctx->current.generation);
        ctx->objects_processed++;
        in_gcs_current_clear(ctx);
        ctx->state = FLB_GCS_STATE_NEXT;
    }
}

static int cb_gcs_collect(struct flb_input_instance *ins, struct flb_config *config,
                          void *in_context)
{
    struct flb_in_gcs *ctx = in_context;
    (void) config;

    if (ctx->done == FLB_TRUE) {
        return 0;
    }

    switch (ctx->state) {
    case FLB_GCS_STATE_LIST:
        gcs_tick_list(ctx);
        break;
    case FLB_GCS_STATE_NEXT:
        gcs_tick_next(ctx);
        break;
    case FLB_GCS_STATE_DOWNLOAD:
        gcs_tick_download(ctx);
        break;
    case FLB_GCS_STATE_EMIT:
        gcs_tick_emit(ctx);
        break;
    default:
        break;
    }

    (void) ins;
    return 0;
}

static int cb_gcs_init(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    int ret;
    const char *env;
    struct flb_in_gcs *ctx;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_in_gcs));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;
    ctx->coll_id = -1;
    env = getenv("FLB_IN_GCS_PLUGIN_UNDER_TEST");
    if (env && strcasecmp(env, "true") == 0) {
        ctx->under_test = FLB_TRUE;
    }
    ctx->state = FLB_GCS_STATE_LIST;
    ctx->has_more_pages = FLB_TRUE;

    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load the configuration");
        gcs_ctx_destroy(ctx);
        return -1;
    }

    if (gcs_validate_config(ctx) == -1) {
        gcs_ctx_destroy(ctx);
        return -1;
    }

    ctx->encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->encoder) {
        flb_plg_error(ins, "could not create the log event encoder");
        gcs_ctx_destroy(ctx);
        return -1;
    }

    if (in_gcs_db_open(ctx) == -1) {
        gcs_ctx_destroy(ctx);
        return -1;
    }

    if (gcs_auth_init(ctx) == -1) {
        flb_plg_error(ins, "could not initialize the authentication");
        gcs_ctx_destroy(ctx);
        return -1;
    }

    if (gcs_network_init(ctx) == -1) {
        gcs_ctx_destroy(ctx);
        return -1;
    }

    flb_input_set_context(ins, ctx);

    ret = flb_input_set_collector_time(ins, cb_gcs_collect, 0, FLB_GCS_TICK_NSEC, config);
    if (ret == -1) {
        flb_plg_error(ins, "could not set up the collector");
        gcs_ctx_destroy(ctx);
        return -1;
    }
    ctx->coll_id = ret;

    flb_plg_info(ins, "rehydrating bucket '%s' from %s", ctx->bucket, ctx->endpoint);
    return 0;
}

static void cb_gcs_pause(void *data, struct flb_config *config)
{
    struct flb_in_gcs *ctx = data;
    (void) config;

    ctx->paused = FLB_TRUE;
    flb_input_collector_pause(ctx->coll_id, ctx->ins);
}

static void cb_gcs_resume(void *data, struct flb_config *config)
{
    struct flb_in_gcs *ctx = data;
    (void) config;

    ctx->paused = FLB_FALSE;

    /* a finished run must not be restarted */
    if (ctx->done == FLB_FALSE) {
        flb_input_collector_resume(ctx->coll_id, ctx->ins);
    }
}

static int cb_gcs_exit(void *data, struct flb_config *config)
{
    (void) config;

    gcs_ctx_destroy(data);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, bucket),
     "Name of the Google Cloud Storage bucket to read the objects from."
    },
    {
     FLB_CONFIG_MAP_STR, "prefix", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, prefix),
     "Only read the objects whose name starts with this prefix."
    },
    {
     FLB_CONFIG_MAP_STR, "start_offset", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, start_offset),
     "Only read the objects whose name is lexicographically greater than or equal "
     "to this value."
    },
    {
     FLB_CONFIG_MAP_STR, "end_offset", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, end_offset),
     "Only read the objects whose name is lexicographically lower than this value."
    },
    {
     FLB_CONFIG_MAP_STR, "endpoint", FLB_GCS_DEFAULT_ENDPOINT,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, endpoint),
     "Storage API endpoint. Use http:// only for tests and emulators."
    },
    {
     FLB_CONFIG_MAP_INT, "page_size", FLB_GCS_DEFAULT_PAGE_SIZE,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, page_size),
     "Maximum number of objects requested on every page of the listing."
    },
    {
     FLB_CONFIG_MAP_INT, "batch_size", FLB_GCS_DEFAULT_BATCH_SIZE,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, batch_size),
     "Maximum number of records ingested on every collector cycle."
    },
    {
     FLB_CONFIG_MAP_SIZE, "max_object_size", FLB_GCS_DEFAULT_MAX_OBJECT,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, max_object_size),
     "Maximum size of an object, also applied to its uncompressed content. Bigger "
     "objects are skipped."
    },
    {
     FLB_CONFIG_MAP_STR, "compression", "auto",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, compression_name),
     "Compression of the objects: auto (detect gzip by its header), none or gzip."
    },
    {
     FLB_CONFIG_MAP_STR, "parser", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, parser_name),
     "Name of a parser used to process every line. When unset, a line that is a "
     "JSON object is used as the record and any other line becomes {\"log\": line}."
    },
    {
     FLB_CONFIG_MAP_STR, "time_key", "date",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, time_key),
     "Key of the record that holds its timestamp (ignored when 'parser' is set). "
     "Use false, off or none to disable it."
    },
    {
     FLB_CONFIG_MAP_STR, "time_format", "auto",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, time_format_name),
     "Format of the timestamp: auto, iso8601, java_sql_timestamp, double, epoch "
     "or epoch_ms."
    },
    {
     FLB_CONFIG_MAP_BOOL, "time_keep", "false",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, time_keep),
     "Keep the time key in the record after it has been used as the timestamp."
    },
    {
     FLB_CONFIG_MAP_STR, "tag_regex", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, tag_regex_pattern),
     "Regular expression applied to the object name. Its first capture group becomes "
     "the tag of the records; if it does not match, the tag of the input is used."
    },
    {
     FLB_CONFIG_MAP_STR, "object_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, object_key),
     "When set, add the name of the object to every record under this key."
    },
#ifdef FLB_HAVE_SQLDB
    {
     FLB_CONFIG_MAP_STR, "db", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, db_path),
     "SQLite file that keeps track of the processed objects (bucket, name and "
     "generation) so that they are not ingested twice."
    },
#endif
    {
     FLB_CONFIG_MAP_BOOL, "exit_on_complete", "false",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, exit_on_complete),
     "Stop Fluent Bit once all the objects have been processed."
    },
    {
     FLB_CONFIG_MAP_INT, "retry_limit", "3",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, retry_limit),
     "Number of times a request is repeated after a temporary error (connection "
     "problems, 429 and 5xx) before giving up."
    },
    {
     FLB_CONFIG_MAP_STR, "google_service_credentials", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, credentials_file),
     "Service account JSON file."
    },
    {
     FLB_CONFIG_MAP_STR, "metadata_server", FLB_GCP_METADATA_SERVER,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, metadata_server),
     "GCE/GKE metadata server used when no credentials file is configured."
    },
    {
     FLB_CONFIG_MAP_BOOL, "enable_identity_federation", "false",
     0, FLB_TRUE, offsetof(struct flb_in_gcs, has_identity_federation),
     "Enable Workload Identity Federation (external account) instead of a "
     "static service account key."
    },
    {
     FLB_CONFIG_MAP_STR, "project_number", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, project_number),
     "GCP project number owning the workload identity pool (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "pool_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, pool_id),
     "Workload identity pool id (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "provider_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, provider_id),
     "Workload identity pool provider id (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "identity_token_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, identity_token_file),
     "Path to the OIDC subject token file used as the federation credential "
     "source (identity federation)."
    },
    {
     FLB_CONFIG_MAP_STR, "google_service_account", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, google_service_account),
     "Service account to impersonate. If unset, the federated token is used "
     "directly against GCS (direct resource access)."
    },
    {
     FLB_CONFIG_MAP_STR, "subject_token_type", FLB_GCP_STS_SUBJECT_TOKEN_TYPE,
     0, FLB_TRUE, offsetof(struct flb_in_gcs, subject_token_type),
     "OIDC subject token type for identity federation."
    },

    /* EOF */
    {0}
};

/*
 * The collector does blocking HTTP requests (sync upstreams, like the gcp_auth helper),
 * so the input runs in its own thread (FLB_INPUT_THREADED) to keep the main event loop
 * responsive. It does not need a coroutine (no FLB_INPUT_CORO): nothing yields.
 * FLB_IO_OPT_TLS allows 'tls on' and the tls.* properties; the default endpoint is
 * https, for which a private TLS context is created when the instance has none.
 */
struct flb_input_plugin in_gcs_plugin = {
    .name         = "gcs",
    .description  = "Google Cloud Storage (rehydrate logs from objects)",
    .cb_init      = cb_gcs_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_gcs_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_gcs_pause,
    .cb_resume    = cb_gcs_resume,
    .cb_exit      = cb_gcs_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET | FLB_INPUT_THREADED | FLB_IO_OPT_TLS
};
