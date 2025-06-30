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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_conf.h"

static int cb_azure_logs_ingestion_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_az_li *ctx;
    (void) config;
    (void) ins;
    (void) data;

    /* Allocate and initialize a context from configuration */
    ctx = flb_az_li_ctx_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    return 0;
}

/* A duplicate function copied from the azure log analytics plugin.
    allocates sds string */
static int az_li_format(const void *in_buf, size_t in_bytes,
                        char **out_buf, size_t *out_size,
                        struct flb_az_li *ctx)
{
    int i;
    int array_size = 0;
    int map_size;
    size_t off = 0;
    double t;
    struct flb_time tm;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *obj;
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

    /* Count number of items */
    array_size = flb_mp_count(in_buf, in_bytes);
    msgpack_unpacked_init(&result);

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, array_size);

    off = 0;
    while (msgpack_unpack_next(&result, in_buf, in_bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        /* Get timestamp */
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* Create temporary msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        msgpack_pack_map(&mp_pck, map_size + 1);

        /* Append the time key */
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->time_key));
        msgpack_pack_str_body(&mp_pck,
                            ctx->time_key,
                            flb_sds_len(ctx->time_key));

        if (ctx->time_generated == FLB_TRUE) {
            /* Append the time value as ISO 8601 */
            gmtime_r(&tm.tm.tv_sec, &tms);
            s = strftime(time_formatted, sizeof(time_formatted) - 1,
                            FLB_PACK_JSON_DATE_ISO8601_FMT, &tms);

            len = snprintf(time_formatted + s,
                            sizeof(time_formatted) - 1 - s,
                            ".%03" PRIu64 "Z",
                            (uint64_t) tm.tm.tv_nsec / 1000000);
            s += len;
            msgpack_pack_str(&mp_pck, s);
            msgpack_pack_str_body(&mp_pck, time_formatted, s);
        }
        else {
            /* Append the time value as millis.nanos */
            t = flb_time_to_double(&tm);
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

    record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    if (!record) {
        flb_errno();
        msgpack_sbuffer_destroy(&mp_sbuf);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);

    *out_buf = record;
    *out_size = flb_sds_len(record);

    return 0;
}

/* Gets OAuth token; (allocates sds string everytime, must deallocate) */
flb_sds_t get_az_li_token(struct flb_az_li *ctx)
{
    int ret = 0;
    char* token;
    size_t token_len;
    flb_sds_t token_return = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }
    /* Retrieve access token only if expired */
    if (flb_oauth2_token_expired(ctx->u_auth) == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "token expired. getting new token");
        /* Clear any previous oauth2 payload content */
        flb_oauth2_payload_clear(ctx->u_auth);

        ret = flb_oauth2_payload_append(ctx->u_auth, "grant_type", 10,
                                        "client_credentials", 18);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "scope", 5, FLB_AZ_LI_AUTH_SCOPE,
                                        sizeof(FLB_AZ_LI_AUTH_SCOPE) - 1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "client_id", 9,
                                        ctx->client_id, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "client_secret", 13,
                                        ctx->client_secret, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        token = flb_oauth2_token_get(ctx->u_auth);

        /* Copy string to prevent race conditions */
        if (!token) {
            flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
            goto token_cleanup;
        }
        flb_plg_debug(ctx->ins, "got azure token");
    }

    /* Reached this code-block means, got new token or token not expired */
    /* Either way we copy the token to a new string */
    token_len = flb_sds_len(ctx->u_auth->token_type) + 2 +
                    flb_sds_len(ctx->u_auth->access_token);
    flb_plg_debug(ctx->ins, "create token header string");
    /* Now create */
    token_return = flb_sds_create_size(token_len);
    if (!token_return) {
        flb_plg_error(ctx->ins, "error creating token buffer");
        goto token_cleanup;
    }
    flb_sds_snprintf(&token_return, flb_sds_alloc(token_return), "%s %s",
                        ctx->u_auth->token_type, ctx->u_auth->access_token);

token_cleanup:
    if (pthread_mutex_unlock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        return NULL;
    }

    return token_return;
}

static void cb_azure_logs_ingestion_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int ret;
    int flush_status;
    size_t b_sent;
    size_t json_payload_size;
    void* final_payload;
    size_t final_payload_size;
    flb_sds_t token;
    struct flb_connection *u_conn;
    struct flb_http_client *c = NULL;
    int is_compressed = FLB_FALSE;
    flb_sds_t json_payload = NULL;
    struct flb_az_li *ctx = out_context;
    (void) i_ins;
    (void) config;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u_dce);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert binary logs into a JSON payload */
    ret = az_li_format(event_chunk->data, event_chunk->size,
                       &json_payload, &json_payload_size, ctx);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Get OAuth2 token */
    token = get_az_li_token(ctx);
    if (!token) {
        flush_status = FLB_RETRY;
        goto cleanup;
    }

    /* Map buffer */
    final_payload = json_payload;
    final_payload_size = json_payload_size;
    if (ctx->compress_enabled == FLB_TRUE) {
        ret = flb_gzip_compress((void *) json_payload, json_payload_size,
                                &final_payload, &final_payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        }
        else {
            is_compressed = FLB_TRUE;
            flb_plg_debug(ctx->ins, "enabled payload gzip compression");
            /* JSON buffer will be cleared at cleanup: */
        }
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->dce_u_url,
                        final_payload, final_payload_size, NULL, 0, NULL, 0);

    if (!c) {
        flb_plg_warn(ctx->ins, "retrying payload bytes=%lu", final_payload_size);
        flush_status = FLB_RETRY;
        goto cleanup;
    }

    /* Append headers */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    if (is_compressed) {
        flb_http_add_header(c, "Content-Encoding", 16, "gzip", 4);
    }
    flb_http_add_header(c, "Authorization", 13, token, flb_sds_len(token));
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);

    /* Execute rest call */
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        flush_status = FLB_RETRY;
        goto cleanup;
    }
    else {
        if (c->resp.status >= 200 && c->resp.status <= 299) {
            flb_plg_info(ctx->ins, "http_status=%i, dcr_id=%s, table=%s",
                         c->resp.status, ctx->dcr_id, ctx->table_name);
            flush_status = FLB_OK;
            goto cleanup;
        }
        else {
            if (c->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "http_status=%i:\n%s",
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_warn(ctx->ins, "http_status=%i", c->resp.status);
            }
            flb_plg_debug(ctx->ins, "retrying payload bytes=%lu", final_payload_size);
            flush_status = FLB_RETRY;
            goto cleanup;
        }
    }

cleanup:
    /* cleanup */
    if (json_payload) {
        flb_sds_destroy(json_payload);
    }

    /* release compressed payload */
    if (is_compressed == FLB_TRUE) {
        flb_free(final_payload);
    }

    if (c) {
        flb_http_client_destroy(c);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }

    /* destory token at last after HTTP call has finished */
    if (token) {
        flb_sds_destroy(token);
    }
    FLB_OUTPUT_RETURN(flush_status);
}

static int cb_azure_logs_ingestion_exit(void *data, struct flb_config *config)
{
    struct flb_az_li *ctx = data;
    flb_plg_debug(ctx->ins, "exiting logs ingestion plugin");
    flb_az_li_ctx_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "tenant_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, tenant_id),
     "Set the tenant ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, client_id),
     "Set the client/app ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_secret", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, client_secret),
     "Set the client secret of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "dce_url", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, dce_url),
     "Data Collection Endpoint(DCE) URI (e.g. "
     "https://la-endpoint-q12a.eastus-1.ingest.monitor.azure.com)"
    },
    {
     FLB_CONFIG_MAP_STR, "dcr_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, dcr_id),
     "Data Collection Rule (DCR) immutable ID"
    },
    {
     FLB_CONFIG_MAP_STR, "table_name", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, table_name),
     "The name of the custom log table, including '_CL' suffix"
    },
    /* optional params */
    {
     FLB_CONFIG_MAP_STR, "time_key", FLB_AZ_LI_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_az_li, time_key),
     "[Optional] Specify the key name where the timestamp will be stored."
    },
    {
     FLB_CONFIG_MAP_BOOL, "time_generated", "false",
     0, FLB_TRUE, offsetof(struct flb_az_li, time_generated),
     "If enabled, will generate a timestamp and append it to JSON. "
     "The key name is set by the 'time_key' parameter"
    },
    {
     FLB_CONFIG_MAP_BOOL, "compress", "false",
     0, FLB_TRUE,  offsetof(struct flb_az_li, compress_enabled),
     "Enable HTTP payload compression (gzip)."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_azure_logs_ingestion_plugin = {
    .name         = "azure_logs_ingestion",
    .description  = "Send logs to Log Analytics with Log Ingestion API",
    .cb_init      = cb_azure_logs_ingestion_init,
    .cb_flush     = cb_azure_logs_ingestion_flush,
    .cb_exit      = cb_azure_logs_ingestion_exit,

    /* Configuration */
    .config_map     = config_map,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
