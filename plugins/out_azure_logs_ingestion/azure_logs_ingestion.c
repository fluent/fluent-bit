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
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_conf.h"
#include "azure_logs_ingestion_batch.h"

static int cb_azure_logs_ingestion_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    const char *buffering;
    struct flb_az_li *ctx;
    (void) config;
    (void) data;

    buffering = flb_output_get_property("buffering_enabled", ins);
    if (buffering != NULL && flb_utils_bool(buffering) == FLB_TRUE) {
        if (ins->tp_workers > 1) {
            flb_plg_error(ins, "buffering supports exactly one output worker");
            return -1;
        }
        ins->tp_workers = 1;
    }

    /* Allocate and initialize a context from configuration */
    ctx = flb_az_li_ctx_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    if (ctx->buffering_enabled == FLB_TRUE) {
        /* OAuth creates its upstream independently of the output helper. Add
         * it to the single output worker's upstream map explicitly. */
        flb_upstream_thread_safe(ctx->u_auth->u);
        mk_list_add(&ctx->u_auth->u->base._head, &ins->upstreams);

        if (az_li_batch_init(ctx) == -1) {
            flb_plg_error(ins, "could not initialize disk-backed batching");
            flb_az_li_ctx_destroy(ctx);
            return -1;
        }
    }

    return 0;
}

static int cb_azure_logs_ingestion_worker_init(void *data,
                                                struct flb_config *config)
{
    struct flb_az_li *ctx = data;

    (void) config;
    if (ctx->buffering_enabled == FLB_FALSE) {
        return 0;
    }
    if (az_li_batch_start_uploader(ctx) == -1) {
        flb_plg_error(ctx->ins, "could not start disk-backed batching uploader");
        return -1;
    }
    return 0;
}

/* A duplicate function copied from the azure log analytics plugin.
    allocates sds string */
static int az_li_format(const void *in_buf, size_t in_bytes,
                        char **out_buf, size_t *out_size,
                        struct flb_az_li *ctx,
                        struct flb_config *config)
{
    int i;
    int ret;
    int array_size = 0;
    int map_size;
    double t;
    struct flb_time tm;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
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
    array_size = flb_mp_count_log_records(in_buf, in_bytes);

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, array_size);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) in_buf, in_bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        return -1;
    }

    while ((ret = flb_log_event_decoder_next(&log_decoder, &log_event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        flb_time_copy(&tm, &log_event.timestamp);

        /* Create temporary msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        map = *log_event.body;
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

    record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                         config->json_escape_unicode);
    if (!record) {
        flb_errno();
        msgpack_sbuffer_destroy(&mp_sbuf);
        flb_log_event_decoder_destroy(&log_decoder);
        return -1;
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_log_event_decoder_destroy(&log_decoder);

    *out_buf = record;
    *out_size = flb_sds_len(record);

    return 0;
}

static int az_li_format_records(const void *in_buf, size_t in_bytes,
                                flb_sds_t **out_records, size_t *out_count,
                                struct flb_az_li *ctx,
                                struct flb_config *config)
{
    int i;
    int ret;
    int map_size;
    int expected;
    int len;
    double timestamp;
    size_t count;
    size_t formatted_size;
    struct tm time_parts;
    struct flb_time event_time;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    msgpack_object map;
    msgpack_sbuffer buffer;
    msgpack_packer packer;
    flb_sds_t record;
    flb_sds_t *records;
    char formatted_time[32];

    expected = flb_mp_count_log_records(in_buf, in_bytes);
    if (expected <= 0) {
        *out_records = NULL;
        *out_count = 0;
        return 0;
    }

    records = flb_calloc(expected, sizeof(flb_sds_t));
    if (records == NULL) {
        return -1;
    }

    ret = flb_log_event_decoder_init(&decoder, (char *) in_buf, in_bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_free(records);
        return -1;
    }

    count = 0;
    while ((ret = flb_log_event_decoder_next(&decoder, &event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        flb_time_copy(&event_time, &event.timestamp);
        map = *event.body;
        map_size = map.via.map.size;

        msgpack_sbuffer_init(&buffer);
        msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);
        msgpack_pack_map(&packer, map_size + 1);
        msgpack_pack_str(&packer, flb_sds_len(ctx->time_key));
        msgpack_pack_str_body(&packer, ctx->time_key, flb_sds_len(ctx->time_key));

        if (ctx->time_generated == FLB_TRUE) {
            gmtime_r(&event_time.tm.tv_sec, &time_parts);
            formatted_size = strftime(formatted_time, sizeof(formatted_time) - 1,
                                      FLB_PACK_JSON_DATE_ISO8601_FMT, &time_parts);
            len = snprintf(formatted_time + formatted_size,
                           sizeof(formatted_time) - 1 - formatted_size,
                           ".%03" PRIu64 "Z",
                           (uint64_t) event_time.tm.tv_nsec / 1000000);
            formatted_size += len;
            msgpack_pack_str(&packer, formatted_size);
            msgpack_pack_str_body(&packer, formatted_time, formatted_size);
        }
        else {
            timestamp = flb_time_to_double(&event_time);
            msgpack_pack_double(&packer, timestamp);
        }

        for (i = 0; i < map_size; i++) {
            msgpack_pack_object(&packer, map.via.map.ptr[i].key);
            msgpack_pack_object(&packer, map.via.map.ptr[i].val);
        }

        record = flb_msgpack_raw_to_json_sds(buffer.data, buffer.size,
                                             config->json_escape_unicode);
        msgpack_sbuffer_destroy(&buffer);
        if (record == NULL) {
            for (i = 0; i < count; i++) {
                flb_sds_destroy(records[i]);
            }
            flb_free(records);
            flb_log_event_decoder_destroy(&decoder);
            return -1;
        }
        records[count++] = record;
    }

    flb_log_event_decoder_destroy(&decoder);
    *out_records = records;
    *out_count = count;
    return 0;
}

static void az_li_records_destroy(flb_sds_t *records, size_t count)
{
    size_t index;

    for (index = 0; index < count; index++) {
        flb_sds_destroy(records[index]);
    }
    flb_free(records);
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

int az_li_send_payload(struct flb_az_li *ctx, const void *payload,
                       size_t payload_size, size_t uncompressed_size,
                       int compressed, int *http_status)
{
    int ret;
    size_t bytes_sent;
    flb_sds_t token;
#ifdef FLB_HAVE_METRICS
    uint64_t metrics_timestamp;
    char *output_name;
#endif
    struct flb_connection *connection;
    struct flb_http_client *client;

    token = NULL;
    client = NULL;
    connection = flb_upstream_conn_get(ctx->u_dce);
    if (connection == NULL) {
        return -1;
    }

    token = get_az_li_token(ctx);
    if (token == NULL) {
        flb_upstream_conn_release(connection);
        return -1;
    }

    client = flb_http_client(connection, FLB_HTTP_POST, ctx->dce_u_url,
                             payload, payload_size, NULL, 0, NULL, 0);
    if (client == NULL) {
        flb_sds_destroy(token);
        flb_upstream_conn_release(connection);
        return -1;
    }

    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
    if (compressed == FLB_TRUE) {
        flb_http_add_header(client, "Content-Encoding", 16, "gzip", 4);
    }
    flb_http_add_header(client, "Authorization", 13, token, flb_sds_len(token));
    flb_http_buffer_size(client, FLB_HTTP_DATA_SIZE_MAX);
    flb_http_set_response_timeout(client, ctx->http_timeout);
    flb_http_set_read_idle_timeout(client, ctx->http_timeout);

#ifdef FLB_HAVE_METRICS
    metrics_timestamp = cfl_time_now();
    output_name = (char *) flb_output_name(ctx->ins);
    pthread_mutex_lock(&ctx->payload_metrics_mutex);
    cmt_histogram_observe(ctx->cmt_uncompressed_payload_size,
                          metrics_timestamp,
                          (double) uncompressed_size,
                          2, (char *[]) {output_name, ctx->dcr_id});
    cmt_histogram_observe(ctx->cmt_http_payload_size,
                          metrics_timestamp,
                          (double) payload_size,
                          2, (char *[]) {output_name, ctx->dcr_id});
    if (payload_size < ctx->http_payload_size_min) {
        ctx->http_payload_size_min = payload_size;
        cmt_gauge_set(ctx->cmt_http_payload_size_min,
                      metrics_timestamp,
                      (double) payload_size,
                      2, (char *[]) {output_name, ctx->dcr_id});
    }
    pthread_mutex_unlock(&ctx->payload_metrics_mutex);
#endif

    ret = flb_http_do(client, &bytes_sent);
    if (ret == 0) {
        *http_status = client->resp.status;
        if (client->resp.status < 200 || client->resp.status > 299) {
            if (client->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "http_status=%i: %s",
                             client->resp.status, client->resp.payload);
            }
            else {
                flb_plg_warn(ctx->ins, "http_status=%i", client->resp.status);
            }
        }
    }
    else {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
    }

    flb_http_client_destroy(client);
    flb_sds_destroy(token);
    flb_upstream_conn_release(connection);
    return ret;
}

static void cb_azure_logs_ingestion_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int ret;
    int status;
    size_t json_payload_size;
    size_t record_count;
    void *final_payload;
    size_t final_payload_size;
    int is_compressed;
    flb_sds_t json_payload;
    flb_sds_t *records;
    struct flb_az_li *ctx;

    (void) i_ins;
    ctx = out_context;
    json_payload = NULL;
    records = NULL;
    record_count = 0;
    final_payload = NULL;
    is_compressed = FLB_FALSE;

    if (ctx->buffering_enabled == FLB_TRUE) {
        /* cb_worker_init failures are not propagated by the output thread
         * framework. Retry timer creation here and never accept durable
         * ownership unless the uploader is active. */
        if (az_li_batch_start_uploader(ctx) == -1) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ret = az_li_format_records(event_chunk->data, event_chunk->size,
                                   &records, &record_count, ctx, config);
        if (ret == -1) {
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        ret = az_li_batch_admit_chunk(ctx, out_flush, event_chunk,
                                      records, record_count);
        az_li_records_destroy(records, record_count);
        if (ret == -1) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    ret = az_li_format(event_chunk->data, event_chunk->size,
                       &json_payload, &json_payload_size, ctx, config);
    if (ret == -1) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    final_payload = json_payload;
    final_payload_size = json_payload_size;
    if (ctx->compress_enabled == FLB_TRUE) {
        ret = flb_gzip_compress(json_payload, json_payload_size,
                                &final_payload, &final_payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot gzip payload, disabling compression");
            final_payload = json_payload;
            final_payload_size = json_payload_size;
        }
        else {
            is_compressed = FLB_TRUE;
        }
    }

    status = 0;
    ret = az_li_send_payload(ctx, final_payload, final_payload_size,
                             json_payload_size, is_compressed, &status);
    if (is_compressed == FLB_TRUE) {
        flb_free(final_payload);
    }
    flb_sds_destroy(json_payload);

    if (ret != 0 || status < 200 || status > 299) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_plg_info(ctx->ins,
                 "http_status=%i, dcr_id=%s, table=%s, request_bytes=%zu",
                 status, ctx->dcr_id, ctx->table_name, final_payload_size);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_azure_logs_ingestion_exit(void *data, struct flb_config *config)
{
    struct flb_az_li *ctx = data;

    if (!ctx) {
        return 0;
    }

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
     FLB_CONFIG_MAP_STR, "auth_url", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, auth_url_override),
     "[Optional] Override the OAuth2 token endpoint."
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
    {
     FLB_CONFIG_MAP_BOOL, "buffering_enabled", "false",
     0, FLB_TRUE, offsetof(struct flb_az_li, buffering_enabled),
     "Persist and batch records locally before ingestion."
    },
    {
     FLB_CONFIG_MAP_STR, "buffer_dir", "/tmp/fluent-bit/azure-logs-ingestion",
     0, FLB_TRUE, offsetof(struct flb_az_li, buffer_dir),
     "Directory for local request batches."
    },
    {
     FLB_CONFIG_MAP_STR, "buffer_key", (char *) NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, buffer_key),
     "Stable storage key for this output instance."
    },
    {
     FLB_CONFIG_MAP_SIZE, "batch_target_size", "900000",
     0, FLB_TRUE, offsetof(struct flb_az_li, batch_target_size),
     "Preferred compressed request size in bytes."
    },
    {
     FLB_CONFIG_MAP_TIME, "batch_timeout", "5s",
     0, FLB_TRUE, offsetof(struct flb_az_li, batch_timeout),
     "Maximum age of an active local batch."
    },
    {
     FLB_CONFIG_MAP_SIZE, "batch_max_uncompressed_size", "16M",
     0, FLB_TRUE, offsetof(struct flb_az_li, batch_max_uncompressed_size),
     "Maximum uncompressed JSON batch size."
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_dir_limit_size", "0",
     0, FLB_TRUE, offsetof(struct flb_az_li, buffer_dir_limit_size),
     "Aggregate bytes owned by outputs sharing buffer_dir."
    },
    {
     FLB_CONFIG_MAP_INT, "upload_retry_limit", "0",
     0, FLB_TRUE, offsetof(struct flb_az_li, upload_retry_limit),
     "Maximum transient retries before quarantine; zero retries indefinitely."
    },
    {
     FLB_CONFIG_MAP_INT, "upload_retry_base", "1",
     0, FLB_TRUE, offsetof(struct flb_az_li, upload_retry_base),
     "Base retry delay in seconds."
    },
    {
     FLB_CONFIG_MAP_TIME, "buffer_receipt_ttl", "24h",
     0, FLB_TRUE, offsetof(struct flb_az_li, buffer_receipt_ttl),
     "Retention for completed chunk receipts; zero retains them indefinitely."
    },
    {
     FLB_CONFIG_MAP_TIME, "http_timeout", "30s",
     0, FLB_TRUE, offsetof(struct flb_az_li, http_timeout),
     "Maximum response and read-idle time for an ingestion request."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_azure_logs_ingestion_plugin = {
    .name         = "azure_logs_ingestion",
    .description  = "Send logs to Log Analytics with Log Ingestion API",
    .cb_init      = cb_azure_logs_ingestion_init,
    .cb_flush       = cb_azure_logs_ingestion_flush,
    .cb_exit        = cb_azure_logs_ingestion_exit,
    .cb_worker_init = cb_azure_logs_ingestion_worker_init,

    /* Configuration */
    .config_map     = config_map,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
