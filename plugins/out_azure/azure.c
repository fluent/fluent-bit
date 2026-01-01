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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <msgpack.h>

#include "azure.h"
#include "azure_conf.h"

static int cb_azure_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_azure *ctx;

    ctx = flb_azure_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

static int azure_format(const void *in_buf, size_t in_bytes,
                        flb_sds_t tag, flb_sds_t *tag_val_out,
                        char **out_buf, size_t *out_size,
                        struct flb_azure *ctx,
                        struct flb_config *config)
{
    int i;
    int array_size = 0;
    int map_size;
    double t;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    flb_sds_t record;
    char time_formatted[32];
    size_t s;
    struct tm tms;
    int len;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    flb_sds_t tmp = NULL;
    int ret;

    /* Count number of items */
    array_size = flb_mp_count(in_buf, in_bytes);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) in_buf, in_bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, array_size);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        /* Create temporary msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        map = *log_event.body;
        map_size = map.via.map.size;

        if (ctx->log_type_key) {
            tmp = flb_ra_translate(ctx->ra_prefix_key,
                                tag, flb_sds_len(tag),
                                map, NULL);
            if (!tmp) {
                flb_plg_error(ctx->ins, "Tagged record translation failed!");
            }
            else if (flb_sds_is_empty(tmp)) {
                flb_plg_warn(ctx->ins, "Record accessor key not matched");
                flb_sds_destroy(tmp);
            }
            else {
                /* tag_val_out must be destroyed by the caller */
                *tag_val_out = tmp;
            }
        }

        msgpack_pack_map(&mp_pck, map_size + 1);

        /* Append the time key */
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->time_key));
        msgpack_pack_str_body(&mp_pck,
                            ctx->time_key,
                            flb_sds_len(ctx->time_key));

        if (ctx->time_generated == FLB_TRUE) {
            /* Append the time value as ISO 8601 */
            gmtime_r(&log_event.timestamp.tm.tv_sec, &tms);

            s = strftime(time_formatted, sizeof(time_formatted) - 1,
                            FLB_PACK_JSON_DATE_ISO8601_FMT, &tms);

            len = snprintf(time_formatted + s,
                            sizeof(time_formatted) - 1 - s,
                            ".%03" PRIu64 "Z",
                            (uint64_t) log_event.timestamp.tm.tv_nsec / 1000000);

            s += len;
            msgpack_pack_str(&mp_pck, s);
            msgpack_pack_str_body(&mp_pck, time_formatted, s);
        } else {
            /* Append the time value as millis.nanos */
            t = flb_time_to_double(&log_event.timestamp);

            msgpack_pack_double(&mp_pck, t);
        }

        /* Append original map k/v */
        for (i = 0; i < map_size; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            msgpack_pack_object(&tmp_pck, k);
            msgpack_pack_object(&tmp_pck, v);
        }
        msgpack_sbuffer_write(&mp_sbuf, tmp_sbuf.data, tmp_sbuf.size);
        msgpack_sbuffer_destroy(&tmp_sbuf);
    }

    record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                         config->json_escape_unicode);
    if (!record) {
        flb_errno();

        flb_log_event_decoder_destroy(&log_decoder);
        msgpack_sbuffer_destroy(&mp_sbuf);

        return -1;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    msgpack_sbuffer_destroy(&mp_sbuf);

    *out_buf = record;
    *out_size = flb_sds_len(record);

    return 0;
}

static int build_headers(struct flb_http_client *c,
                         flb_sds_t log_type,
                         size_t content_length,
                         struct flb_azure *ctx)
{
    int len;
    char *auth;
    char tmp[256];
    time_t t;
    size_t size;
    size_t olen;
    flb_sds_t rfc1123date;
    flb_sds_t str_hash;
    struct tm tm = {0};
    unsigned char hmac_hash[32] = {0};
    int result;

    /* Format Date */
    rfc1123date = flb_sds_create_size(32);
    if (!rfc1123date) {
        flb_errno();
        return -1;
    }

    t = time(NULL);
    if (!gmtime_r(&t, &tm)) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return -1;
    }
    size = strftime(rfc1123date,
                    flb_sds_alloc(rfc1123date) - 1,
                    "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (size <= 0) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return -1;
    }
    flb_sds_len_set(rfc1123date, size);

    /* Compose source string for the hash */
    str_hash = flb_sds_create_size(256);
    if (!str_hash) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        return -1;
    }

    len = snprintf(tmp, sizeof(tmp) - 1, "%zu\n", content_length);
    flb_sds_cat(str_hash, "POST\n", 5);
    flb_sds_cat(str_hash, tmp, len);
    flb_sds_cat(str_hash, "application/json\n", 17);
    flb_sds_cat(str_hash, "x-ms-date:", 10);
    flb_sds_cat(str_hash, rfc1123date, flb_sds_len(rfc1123date));
    flb_sds_cat(str_hash, "\n", 1);
    flb_sds_cat(str_hash, FLB_AZURE_RESOURCE, sizeof(FLB_AZURE_RESOURCE) - 1);

    /* Authorization signature */
    result = flb_hmac_simple(FLB_HASH_SHA256,
                             (unsigned char *) ctx->dec_shared_key,
                             flb_sds_len(ctx->dec_shared_key),
                             (unsigned char *) str_hash,
                             flb_sds_len(str_hash),
                             hmac_hash,
                             sizeof(hmac_hash));

    if (result != FLB_CRYPTO_SUCCESS) {
        flb_sds_destroy(rfc1123date);
        flb_sds_destroy(str_hash);
        return -1;
    }

    /* Encoded hash */
    result = flb_base64_encode((unsigned char *) &tmp, sizeof(tmp) - 1, &olen,
                               hmac_hash, sizeof(hmac_hash));
    tmp[olen] = '\0';

    /* Append headers */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Log-Type", 8,
                        log_type, flb_sds_len(log_type));
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    flb_http_add_header(c, "x-ms-date", 9, rfc1123date,
                        flb_sds_len(rfc1123date));
    if (ctx->time_generated == FLB_TRUE) {
        /* Use time value as time-generated within azure */
        flb_http_add_header(c, "time-generated-field", 20, ctx->time_key, flb_sds_len(ctx->time_key));
    }

    size = 32 + flb_sds_len(ctx->customer_id) + olen;
    auth = flb_malloc(size);
    if (!auth) {
        flb_errno();
        flb_sds_destroy(rfc1123date);
        flb_sds_destroy(str_hash);
        return -1;
    }


    len = snprintf(auth, size, "SharedKey %s:%s",
                   ctx->customer_id, tmp);
    flb_http_add_header(c, "Authorization", 13, auth, len);

    /* release resources */
    flb_sds_destroy(rfc1123date);
    flb_sds_destroy(str_hash);
    flb_free(auth);

    return 0;
}

static void cb_azure_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int ret;
    size_t b_sent;
    char *buf_data;
    size_t buf_size;
    struct flb_azure *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    flb_sds_t payload;
    flb_sds_t final_log_type = NULL;
    (void) i_ins;
    (void) config;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert binary logs into a JSON payload */
    ret = azure_format(event_chunk->data, event_chunk->size,
                       event_chunk->tag, &final_log_type, &buf_data, &buf_size, ctx,
                       config);
    /* If cannot get matching record using log_type_prefix, use log_type directly */
    if (!final_log_type) {
        final_log_type = ctx->log_type;
    }

    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    payload = (flb_sds_t) buf_data;

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        buf_data, buf_size, NULL, 0, NULL, 0);
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);

    /* Append headers and Azure signature */
    ret = build_headers(c, final_log_type, flb_sds_len(payload), ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error composing signature");
        flb_sds_destroy(payload);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        goto retry;
    }
    else {
        if (c->resp.status >= 200 && c->resp.status <= 299) {
            flb_plg_info(ctx->ins, "customer_id=%s, HTTP status=%i",
                         ctx->customer_id, c->resp.status);
        }
        else {
            if (c->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "http_status=%i:\n%s",
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_warn(ctx->ins, "http_status=%i", c->resp.status);
            }
            goto retry;
        }
    }

    /* Cleanup */
    if (final_log_type != ctx->log_type) {
        flb_sds_destroy(final_log_type);
    }
    flb_http_client_destroy(c);
    flb_sds_destroy(payload);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    flb_http_client_destroy(c);
    flb_sds_destroy(payload);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int cb_azure_exit(void *data, struct flb_config *config)
{
    struct flb_azure *ctx = data;

    flb_azure_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "customer_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure, customer_id),
     "Customer ID or WorkspaceID string."
    },

    {
     FLB_CONFIG_MAP_STR, "shared_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure, shared_key),
     "The primary or the secondary Connected Sources client authentication key."
    },

    {
     FLB_CONFIG_MAP_STR, "log_type", FLB_AZURE_LOG_TYPE,
     0, FLB_TRUE, offsetof(struct flb_azure, log_type),
    "The name of the event type."
    },

    {
     FLB_CONFIG_MAP_STR, "log_type_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_azure, log_type_key),
     "If included, the value for this key will be looked upon in the record "
     "and if present, will over-write the `log_type`. If the key/value "
     "is not found in the record then the `log_type` option will be used. "
    },

    {
     FLB_CONFIG_MAP_STR, "time_key", FLB_AZURE_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_azure, time_key),
    "Optional parameter to specify the key name where the timestamp will be stored."
    },

    {
     FLB_CONFIG_MAP_BOOL, "time_generated", "false",
     0, FLB_TRUE, offsetof(struct flb_azure, time_generated),
     "If enabled, the HTTP request header 'time-generated-field' will be included "
     "so Azure can override the timestamp with the key specified by 'time_key' "
     "option."
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_azure_plugin = {
    .name         = "azure",
    .description  = "Send events to Azure HTTP Event Collector",
    .cb_init      = cb_azure_init,
    .cb_flush     = cb_azure_flush,
    .cb_exit      = cb_azure_exit,

    /* Configuration */
    .config_map     = config_map,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
