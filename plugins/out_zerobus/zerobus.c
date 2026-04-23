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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_mp.h>

#include <msgpack.h>
#include <time.h>
#include <string.h>

#include "zerobus.h"

/*
 * Prepend "https://" to url if no scheme is present.
 * Returns a newly allocated sds string; caller must flb_sds_destroy it.
 * Returns NULL on allocation failure.
 */
static flb_sds_t ensure_url_scheme(const char *url)
{
    size_t url_len;
    flb_sds_t out;
    flb_sds_t tmp;

    if (strncmp(url, "https://", 8) == 0 ||
        strncmp(url, "http://", 7) == 0) {
        return flb_sds_create(url);
    }

    url_len = strlen(url);
    out = flb_sds_create_size(url_len + 9);
    if (!out) {
        return NULL;
    }
    tmp = flb_sds_cat(out, "https://", 8);
    if (!tmp) {
        flb_sds_destroy(out);
        return NULL;
    }
    out = tmp;
    tmp = flb_sds_cat(out, url, url_len);
    if (!tmp) {
        flb_sds_destroy(out);
        return NULL;
    }
    return tmp;
}

/*
 * Format tm as an RFC 3339 timestamp with nanosecond precision into buf.
 * Returns the number of characters written (excluding the null terminator),
 * or -1 if gmtime_r fails.
 */
static int format_timestamp_rfc3339nano(struct flb_time *tm,
                                        char *buf, size_t size)
{
    struct tm gmt;
    time_t sec = (time_t) tm->tm.tv_sec;

    if (!gmtime_r(&sec, &gmt)) {
        return -1;
    }
    return snprintf(buf, size,
                    "%04d-%02d-%02dT%02d:%02d:%02d.%09luZ",
                    gmt.tm_year + 1900, gmt.tm_mon + 1, gmt.tm_mday,
                    gmt.tm_hour, gmt.tm_min, gmt.tm_sec,
                    (unsigned long) tm->tm.tv_nsec);
}

/*
 * Return 1 if key (with length key_len) matches any entry in log_keys,
 * 0 otherwise.
 */
static int key_in_log_keys(const char *key, int key_len,
                           struct mk_list *log_keys)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, log_keys) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        if ((int) flb_sds_len(entry->str) == key_len &&
            memcmp(entry->str, key, key_len) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Return 1 if msgpack object k is a string of length name_len equal to name,
 * 0 otherwise.
 */
static inline int str_key_equals(const msgpack_object *k,
                                 const char *name, int name_len)
{
    return k->type == MSGPACK_OBJECT_STR &&
           (int) k->via.str.size == name_len &&
           memcmp(k->via.str.ptr, name, name_len) == 0;
}

/*
 * Log an error from a failed CResult and free its error_message.
 * Returns FLB_RETRY if is_retryable, FLB_ERROR otherwise.
 */
static int log_cresult_error(struct flb_output_instance *ins,
                             CResult *r, const char *context)
{
    int ret = r->is_retryable ? FLB_RETRY : FLB_ERROR;

    flb_plg_error(ins, "%s: %s",
                  context,
                  r->error_message ? r->error_message : "unknown");
    if (r->error_message) {
        zerobus_free_error_message(r->error_message);
        r->error_message = NULL;
    }
    return ret;
}

/*
 * Convert a log event body to a JSON string for ZeroBus ingestion.
 *
 * Matches the Go plugin's recordToJSON: applies log_keys filter, then
 * injects raw_log_key (full pre-filter record), time_key, and _tag
 * without overwriting existing keys.
 *
 * Uses flb_mp_map_header for single-pass packing (no pre-counting).
 * The caller-owned msgpack_sbuffer is reused across records.
 */
static flb_sds_t record_to_json(struct flb_out_zerobus *ctx,
                                msgpack_object *body,
                                struct flb_time *tm,
                                const char *tag, int tag_len,
                                msgpack_sbuffer *sbuf,
                                int escape_unicode)
{
    int i;
    int has_time_key = 0;
    int has_tag_key  = 0;
    int has_raw_key  = 0;
    int time_key_len;
    int raw_key_len;
    int include;
    char *raw_json = NULL;
    char time_buf[64];
    msgpack_packer pk;
    struct flb_mp_map_header mh;
    flb_sds_t json;

    if (body->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    msgpack_object_map *map = &body->via.map;
    time_key_len = (ctx->time_key) ? (int) flb_sds_len(ctx->time_key) : 0;
    raw_key_len  = (ctx->raw_log_key) ? (int) flb_sds_len(ctx->raw_log_key) : 0;

    msgpack_sbuffer_clear(sbuf);
    msgpack_packer_init(&pk, sbuf, msgpack_sbuffer_write);
    flb_mp_map_header_init(&mh, &pk);

    /* Single pass: pack included body keys, track collision flags */
    for (i = 0; i < (int) map->size; i++) {
        msgpack_object *k = &map->ptr[i].key;

        if (ctx->log_keys) {
            if (k->type != MSGPACK_OBJECT_STR) {
                continue;
            }
            include = key_in_log_keys(k->via.str.ptr,
                                      (int) k->via.str.size,
                                      ctx->log_keys);
            if (!include) {
                continue;
            }
        }

        flb_mp_map_header_append(&mh);
        msgpack_pack_object(&pk, map->ptr[i].key);
        msgpack_pack_object(&pk, map->ptr[i].val);

        if (k->type == MSGPACK_OBJECT_STR) {
            if (time_key_len > 0 &&
                str_key_equals(k, ctx->time_key, time_key_len)) {
                has_time_key = 1;
            }
            if (ctx->add_tag && str_key_equals(k, "_tag", 4)) {
                has_tag_key = 1;
            }
            if (raw_key_len > 0 &&
                str_key_equals(k, ctx->raw_log_key, raw_key_len)) {
                has_raw_key = 1;
            }
        }
    }

    if (raw_key_len > 0 && !has_raw_key) {
        size_t rj_len;

        /*
         * Serialize the original (pre-filter) body only when the key is
         * absent. Deferring to here avoids a full serialize+discard on
         * every record that already carries the field.
         * body is unchanged by the loop above, so the result is identical
         * to capturing it before filtering (matching Go's json.Marshal(m)).
         */
        raw_json = flb_msgpack_to_json_str(0, body, escape_unicode);
        if (!raw_json) {
            return NULL;
        }
        rj_len = strlen(raw_json);

        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&pk, raw_key_len);
        msgpack_pack_str_body(&pk, ctx->raw_log_key, raw_key_len);
        msgpack_pack_str(&pk, rj_len);
        msgpack_pack_str_body(&pk, raw_json, rj_len);
    }

    if (time_key_len > 0 && !has_time_key) {
        int time_len = format_timestamp_rfc3339nano(tm, time_buf, sizeof(time_buf));
        if (time_len > 0) {
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(&pk, time_key_len);
            msgpack_pack_str_body(&pk, ctx->time_key, time_key_len);
            msgpack_pack_str(&pk, time_len);
            msgpack_pack_str_body(&pk, time_buf, time_len);
        }
    }

    if (ctx->add_tag && tag_len > 0 && !has_tag_key) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&pk, 4);
        msgpack_pack_str_body(&pk, "_tag", 4);
        msgpack_pack_str(&pk, tag_len);
        msgpack_pack_str_body(&pk, tag, tag_len);
    }

    flb_mp_map_header_end(&mh);

    json = flb_msgpack_raw_to_json_sds(sbuf->data, sbuf->size, escape_unicode);

    if (raw_json) {
        flb_free(raw_json);
    }

    return json;
}

/*
 * Plugin init callback: validate required config, then create the ZeroBus
 * SDK handle and stream. Returns 0 on success, -1 on failure.
 */
static int cb_zerobus_init(struct flb_output_instance *ins,
                           struct flb_config *config,
                           void *data)
{
    int ret;
    const char *tmp;
    struct flb_out_zerobus *ctx;
    CResult result;
    CStreamConfigurationOptions opts;

    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_zerobus));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /*
     * Both endpoint and workspace_url get https:// prepended when no
     * scheme is present.
     */
    tmp = flb_output_get_property("endpoint", ins);
    if (!tmp || strlen(tmp) == 0) {
        flb_plg_error(ins, "'endpoint' is required");
        goto init_error;
    }
    ctx->endpoint = ensure_url_scheme(tmp);
    if (!ctx->endpoint) {
        goto init_error;
    }

    tmp = flb_output_get_property("workspace_url", ins);
    if (!tmp || strlen(tmp) == 0) {
        flb_plg_error(ins, "'workspace_url' is required");
        goto init_error;
    }
    ctx->workspace_url = ensure_url_scheme(tmp);
    if (!ctx->workspace_url) {
        goto init_error;
    }

    if (!ctx->table_name || flb_sds_len(ctx->table_name) == 0) {
        flb_plg_error(ins, "'table_name' is required");
        goto init_error;
    }
    if (!ctx->client_id || flb_sds_len(ctx->client_id) == 0) {
        flb_plg_error(ins, "'client_id' is required");
        goto init_error;
    }
    if (!ctx->client_secret || flb_sds_len(ctx->client_secret) == 0) {
        flb_plg_error(ins, "'client_secret' is required");
        goto init_error;
    }

    memset(&result, 0, sizeof(result));
    ctx->sdk = zerobus_sdk_new(ctx->endpoint,
                               ctx->workspace_url,
                               &result);
    if (!ctx->sdk || !result.success) {
        log_cresult_error(ins, &result, "failed to create ZeroBus SDK");
        goto init_error;
    }

    if (strncmp(ctx->endpoint, "http://", 7) == 0) {
        zerobus_sdk_set_use_tls(ctx->sdk, false);
    }

    opts = zerobus_get_default_config();
    opts.record_type = ZEROBUS_RECORD_TYPE_JSON;

    memset(&result, 0, sizeof(result));
    ctx->stream = zerobus_sdk_create_stream(ctx->sdk,
                                            ctx->table_name,
                                            NULL, 0,
                                            ctx->client_id,
                                            ctx->client_secret,
                                            &opts,
                                            &result);
    if (!ctx->stream || !result.success) {
        log_cresult_error(ins, &result, "failed to create ZeroBus stream");
        zerobus_sdk_free(ctx->sdk);
        ctx->sdk = NULL;
        goto init_error;
    }

    flb_plg_info(ins, "connected to %s, table: %s",
                 ctx->endpoint, ctx->table_name);

    flb_output_set_context(ins, ctx);
    return 0;

init_error:
    if (ctx->endpoint) {
        flb_sds_destroy(ctx->endpoint);
    }
    if (ctx->workspace_url) {
        flb_sds_destroy(ctx->workspace_url);
    }
    flb_free(ctx);
    return -1;
}

/*
 * Plugin flush callback: decode incoming log events, convert each to JSON,
 * and ingest the batch via ZeroBus. Waits for server-side acknowledgment
 * before returning. Returns FLB_OK, FLB_RETRY, or FLB_ERROR via
 * FLB_OUTPUT_RETURN.
 */
static void cb_zerobus_flush(struct flb_event_chunk *event_chunk,
                             struct flb_output_flush *out_flush,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    int ret;
    size_t capacity;
    size_t num_records = 0;
    int convert_errors = 0;
    struct flb_out_zerobus *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    flb_sds_t *json_records = NULL;
    flb_sds_t json;
    msgpack_sbuffer sbuf;
    CResult result;
    int64_t offset;
    size_t i;
    int tag_len;

    (void) i_ins;

    tag_len = event_chunk->tag ? (int) flb_sds_len(event_chunk->tag) : 0;

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "log event decoder initialization error: %d", ret);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    capacity = event_chunk->total_events > 0 ? event_chunk->total_events : 64;
    json_records = flb_malloc(sizeof(flb_sds_t) * capacity);
    if (!json_records) {
        flb_log_event_decoder_destroy(&log_decoder);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Reuse a single sbuffer across all record conversions */
    msgpack_sbuffer_init(&sbuf);

    while (flb_log_event_decoder_next(&log_decoder,
                                      &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        json = record_to_json(ctx,
                              log_event.body,
                              &log_event.timestamp,
                              event_chunk->tag, tag_len,
                              &sbuf,
                              config->json_escape_unicode);
        if (!json) {
            convert_errors++;
            flb_plg_warn(ctx->ins, "failed to convert record to JSON");
            continue;
        }

        if (num_records == capacity) {
            size_t new_cap = capacity * 2;
            flb_sds_t *tmp = flb_realloc(json_records,
                                          sizeof(flb_sds_t) * new_cap);
            if (!tmp) {
                flb_plg_error(ctx->ins,
                              "realloc failed, retrying entire batch");
                flb_sds_destroy(json);
                for (i = 0; i < num_records; i++) {
                    flb_sds_destroy(json_records[i]);
                }
                flb_free(json_records);
                msgpack_sbuffer_destroy(&sbuf);
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            json_records = tmp;
            capacity     = new_cap;
        }

        json_records[num_records] = json;
        num_records++;
    }

    msgpack_sbuffer_destroy(&sbuf);
    flb_log_event_decoder_destroy(&log_decoder);

    if (num_records == 0) {
        flb_free(json_records);
        if (convert_errors > 0) {
            flb_plg_error(ctx->ins,
                          "all %d records failed conversion", convert_errors);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    if (convert_errors > 0) {
        flb_plg_warn(ctx->ins,
                     "skipped %d records due to conversion errors",
                     convert_errors);
    }

    /* flb_sds_t is char*, so the cast to const char** is safe */
    memset(&result, 0, sizeof(result));
    offset = zerobus_stream_ingest_json_records(ctx->stream,
                                                (const char **) json_records,
                                                num_records,
                                                &result);
    if (!result.success) {
        ret = log_cresult_error(ctx->ins, &result, "ingestion error");
        goto flush_cleanup;
    }

    memset(&result, 0, sizeof(result));
    zerobus_stream_wait_for_offset(ctx->stream, offset, &result);
    if (!result.success) {
        ret = log_cresult_error(ctx->ins, &result, "wait_for_offset error");
        goto flush_cleanup;
    }

    ret = FLB_OK;

flush_cleanup:
    for (i = 0; i < num_records; i++) {
        flb_sds_destroy(json_records[i]);
    }
    flb_free(json_records);

    FLB_OUTPUT_RETURN(ret);
}

/*
 * Plugin exit callback: close the ZeroBus stream, free the SDK handle,
 * and release the plugin context. Returns 0.
 */
static int cb_zerobus_exit(void *data, struct flb_config *config)
{
    struct flb_out_zerobus *ctx = data;
    CResult result;

    (void) config;

    if (!ctx) {
        return 0;
    }

    if (ctx->stream) {
        memset(&result, 0, sizeof(result));
        zerobus_stream_close(ctx->stream, &result);
        if (!result.success && result.error_message) {
            flb_plg_error(ctx->ins, "stream close error: %s",
                          result.error_message);
            zerobus_free_error_message(result.error_message);
        }
        zerobus_stream_free(ctx->stream);
    }

    if (ctx->sdk) {
        zerobus_sdk_free(ctx->sdk);
    }

    if (ctx->endpoint) {
        flb_sds_destroy(ctx->endpoint);
    }
    if (ctx->workspace_url) {
        flb_sds_destroy(ctx->workspace_url);
    }

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "endpoint", NULL,
     0, FLB_FALSE, 0,
     "ZeroBus gRPC endpoint URL (https:// prepended if no scheme)"
    },
    {
     FLB_CONFIG_MAP_STR, "workspace_url", NULL,
     0, FLB_FALSE, 0,
     "Databricks workspace URL"
    },
    {
     FLB_CONFIG_MAP_STR, "table_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_zerobus, table_name),
     "Fully qualified table name (catalog.schema.table)"
    },
    {
     FLB_CONFIG_MAP_STR, "client_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_zerobus, client_id),
     "OAuth2 client ID for authentication"
    },
    {
     FLB_CONFIG_MAP_STR, "client_secret", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_zerobus, client_secret),
     "OAuth2 client secret for authentication"
    },
    {
     FLB_CONFIG_MAP_BOOL, "add_tag", "true",
     0, FLB_TRUE, offsetof(struct flb_out_zerobus, add_tag),
     "Add Fluent Bit tag as _tag field in each record"
    },
    {
     FLB_CONFIG_MAP_STR, "time_key", "_time",
     0, FLB_TRUE, offsetof(struct flb_out_zerobus, time_key),
     "Key name for the injected timestamp (RFC 3339 with nanoseconds)"
    },
    {
     FLB_CONFIG_MAP_CLIST, "log_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_zerobus, log_keys),
     "Comma-separated list of record keys to include (all if unset)"
    },
    {
     FLB_CONFIG_MAP_STR, "raw_log_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_zerobus, raw_log_key),
     "If set, store the full original record as a JSON string under this key"
    },
    {0}
};

struct flb_output_plugin out_zerobus_plugin = {
    .name         = "zerobus",
    .description  = "Send logs to Databricks ZeroBus",
    .cb_init      = cb_zerobus_init,
    .cb_flush     = cb_zerobus_flush,
    .cb_exit      = cb_zerobus_exit,
    .config_map   = config_map,
    .event_type   = FLB_OUTPUT_LOGS,
    .flags        = 0,
    .workers      = 1,
};
