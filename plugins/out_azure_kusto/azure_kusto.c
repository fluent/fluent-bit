/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "azure_kusto.h"
#include "azure_kusto_conf.h"
#include "azure_kusto_ingest.h"

/* Create a new oauth2 context and get a oauth2 token */
static int azure_kusto_get_oauth2_token(struct flb_azure_kusto *ctx)
{
    int ret;
    char *token;

    /* Clear any previous oauth2 payload content */
    flb_oauth2_payload_clear(ctx->o);

    ret = flb_oauth2_payload_append(ctx->o, "grant_type", 10, "client_credentials", 18);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "scope", 5, FLB_AZURE_KUSTO_SCOPE, 39);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "client_id", 9, ctx->client_id, -1);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o, "client_secret", 13, ctx->client_secret, -1);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        return -1;
    }

    /* Retrieve access token */
    token = flb_oauth2_token_get(ctx->o);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        return -1;
    }

    return 0;
}

flb_sds_t get_azure_kusto_token(struct flb_azure_kusto *ctx)
{
    int ret = 0;
    flb_sds_t output = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }

    if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        ret = azure_kusto_get_oauth2_token(ctx);
    }

    /* Copy string to prevent race conditions (get_oauth2 can free the string) */
    if (ret == 0) {
        output = flb_sds_create_size(flb_sds_len(ctx->o->token_type) +
                                     flb_sds_len(ctx->o->access_token) + 2);
        if (!output) {
            flb_plg_error(ctx->ins, "error creating token buffer");
            return NULL;
        }
        flb_sds_snprintf(&output, flb_sds_alloc(output), "%s %s", ctx->o->token_type,
                         ctx->o->access_token);
    }

    if (pthread_mutex_unlock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        if (output) {
            flb_sds_destroy(output);
        }
        return NULL;
    }

    return output;
}

/**
 * Executes a control command against kusto's endpoint
 *
 * @param ctx       Plugin's context
 * @param csl       Kusto's control command
 * @return flb_sds_t      Returns the response or NULL on error.
 */
flb_sds_t execute_ingest_csl_command(struct flb_azure_kusto *ctx, const char *csl)
{
    flb_sds_t token;
    flb_sds_t body;
    size_t b_sent;
    int ret;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    flb_sds_t resp = NULL;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);

    if (u_conn) {
        token = get_azure_kusto_token(ctx);

        if (token) {
            /* Compose request body */
            body = flb_sds_create_size(sizeof(FLB_AZURE_KUSTO_MGMT_BODY_TEMPLATE) - 1 +
                                       strlen(csl));

            if (body) {
                flb_sds_snprintf(&body, flb_sds_alloc(body),
                                 FLB_AZURE_KUSTO_MGMT_BODY_TEMPLATE, csl);

                /* Compose HTTP Client request */
                c = flb_http_client(u_conn, FLB_HTTP_POST, FLB_AZURE_KUSTO_MGMT_URI_PATH,
                                    body, flb_sds_len(body), NULL, 0, NULL, 0);

                if (c) {
                    /* Add headers */
                    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
                    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
                    flb_http_add_header(c, "Accept", 6, "application/json", 16);
                    flb_http_add_header(c, "Authorization", 13, token,
                                        flb_sds_len(token));
                    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX * 10);

                    /* Send HTTP request */
                    ret = flb_http_do(c, &b_sent);
                    flb_plg_debug(
                        ctx->ins,
                        "Kusto ingestion command request http_do=%i, HTTP Status: %i",
                        ret, c->resp.status);

                    if (ret == 0) {
                        if (c->resp.status == 200) {
                            /* Copy payload response to the response param */
                            resp =
                                flb_sds_create_len(c->resp.payload, c->resp.payload_size);
                        }
                        else if (c->resp.payload_size > 0) {
                            flb_plg_debug(ctx->ins, "Request failed and returned: \n%s",
                                          c->resp.payload);
                        }
                        else {
                            flb_plg_debug(ctx->ins, "Request failed");
                        }
                    }
                    else {
                        flb_plg_error(ctx->ins, "cannot send HTTP request");
                    }

                    flb_http_client_destroy(c);
                }
                else {
                    flb_plg_error(ctx->ins, "cannot create HTTP client context");
                }

                flb_sds_destroy(body);
            }
            else {
                flb_plg_error(ctx->ins, "cannot construct request body");
            }

            flb_sds_destroy(token);
        }
        else {
            flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        }

        flb_upstream_conn_release(u_conn);
    }
    else {
        flb_plg_error(ctx->ins, "cannot create upstream connection");
    }

    return resp;
}

static int cb_azure_kusto_init(struct flb_output_instance *ins, struct flb_config *config,
                               void *data)
{
    int io_flags = FLB_IO_TLS;
    struct flb_azure_kusto *ctx;

    /* Create config context */
    ctx = flb_azure_kusto_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    flb_output_set_context(ins, ctx);

    /* Network mode IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create mutex for acquiring oauth tokens  and getting ingestion resources (they
     * are shared across flush coroutines)
     */
    pthread_mutex_init(&ctx->token_mutex, NULL);
    pthread_mutex_init(&ctx->resources_mutex, NULL);

    /*
     * Create upstream context for Kusto Ingestion endpoint
     */
    ctx->u = flb_upstream_create_url(config, ctx->ingestion_endpoint, io_flags, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }

    /* Create oauth2 context */
    ctx->o =
        flb_oauth2_create(ctx->config, ctx->oauth_url, FLB_AZURE_KUSTO_TOKEN_REFRESH);
    if (!ctx->o) {
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }
    flb_output_upstream_set(ctx->u, ins);

    return 0;
}

static int azure_kusto_format(struct flb_azure_kusto *ctx, const char *tag, int tag_len,
                              const void *data, size_t bytes, void **out_data,
                              size_t *out_size)
{
    int records = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    /* for sub msgpack objs */
    int map_size;
    struct tm tms;
    char time_formatted[32];
    size_t s;
    int len;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event         log_event;
    int                          ret;
    /* output buffer */
    flb_sds_t out_buf;

    /* Create array for all records */
    records = flb_mp_count(data, bytes);
    if (records <= 0) {
        flb_plg_error(ctx->ins, "error counting msgpack entries");
        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, records);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map_size = 1;
        if (ctx->include_time_key == FLB_TRUE) {
            map_size++;
        }

        if (ctx->include_tag_key == FLB_TRUE) {
            map_size++;
        }

        msgpack_pack_map(&mp_pck, map_size);

        /* include_time_key */
        if (ctx->include_time_key == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, flb_sds_len(ctx->time_key));
            msgpack_pack_str_body(&mp_pck, ctx->time_key, flb_sds_len(ctx->time_key));

            /* Append the time value as ISO 8601 */
            gmtime_r(&log_event.timestamp.tm.tv_sec, &tms);
            s = strftime(time_formatted, sizeof(time_formatted) - 1,
                         FLB_PACK_JSON_DATE_ISO8601_FMT, &tms);

            len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                           ".%03" PRIu64 "Z",
                           (uint64_t)log_event.timestamp.tm.tv_nsec / 1000000);
            s += len;
            msgpack_pack_str(&mp_pck, s);
            msgpack_pack_str_body(&mp_pck, time_formatted, s);
        }

        /* include_tag_key */
        if (ctx->include_tag_key == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, flb_sds_len(ctx->tag_key));
            msgpack_pack_str_body(&mp_pck, ctx->tag_key, flb_sds_len(ctx->tag_key));
            msgpack_pack_str(&mp_pck, tag_len);
            msgpack_pack_str_body(&mp_pck, tag, tag_len);
        }

        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->log_key));
        msgpack_pack_str_body(&mp_pck, ctx->log_key, flb_sds_len(ctx->log_key));
        msgpack_pack_object(&mp_pck, *log_event.body);
    }

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);

    /* Cleanup */
    flb_log_event_decoder_destroy(&log_decoder);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

static void cb_azure_kusto_flush(struct flb_event_chunk *event_chunk,
                                 struct flb_output_flush *out_flush,
                                 struct flb_input_instance *i_ins, void *out_context,
                                 struct flb_config *config)
{
    int ret;
    flb_sds_t json;
    size_t json_size;
    size_t tag_len;
    struct flb_azure_kusto *ctx = out_context;

    (void)i_ins;
    (void)config;

    flb_plg_trace(ctx->ins, "flushing bytes %zu", event_chunk->size);

    tag_len = flb_sds_len(event_chunk->tag);

    /* Load or refresh ingestion resources */
    ret = azure_kusto_load_ingestion_resources(ctx, config);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot load ingestion resources");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Reformat msgpack to JSON payload */
    ret = azure_kusto_format(ctx, event_chunk->tag, tag_len, event_chunk->data,
                             event_chunk->size, (void **)&json, &json_size);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot reformat data into json");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = azure_kusto_queued_ingestion(ctx, event_chunk->tag, tag_len, json, json_size);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot perform queued ingestion");
        flb_sds_destroy(json);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Cleanup */
    flb_sds_destroy(json);

    /* Done */
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_azure_kusto_exit(void *data, struct flb_config *config)
{
    struct flb_azure_kusto *ctx = data;

    if (!ctx) {
        return -1;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
        ctx->u = NULL;
    }

    flb_azure_kusto_conf_destroy(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "tenant_id", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, tenant_id),
     "Set the tenant ID of the AAD application used for authentication"},
    {FLB_CONFIG_MAP_STR, "client_id", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, client_id),
     "Set the client ID (Application ID) of the AAD application used for authentication"},
    {FLB_CONFIG_MAP_STR, "client_secret", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, client_secret),
     "Set the client secret (Application Password) of the AAD application used for "
     "authentication"},
    {FLB_CONFIG_MAP_STR, "ingestion_endpoint", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, ingestion_endpoint),
     "Set the Kusto cluster's ingestion endpoint URL (e.g. "
     "https://ingest-mycluster.eastus.kusto.windows.net)"},
    {FLB_CONFIG_MAP_STR, "database_name", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, database_name), "Set the database name"},
    {FLB_CONFIG_MAP_STR, "table_name", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, table_name), "Set the table name"},
    {FLB_CONFIG_MAP_STR, "ingestion_mapping_reference", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, ingestion_mapping_reference),
     "Set the ingestion mapping reference"},
    {FLB_CONFIG_MAP_STR, "log_key", FLB_AZURE_KUSTO_DEFAULT_LOG_KEY, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, log_key), "The key name of event payload"},
    {FLB_CONFIG_MAP_BOOL, "include_tag_key", "true", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, include_tag_key),
     "If enabled, tag is appended to output. "
     "The key name is used 'tag_key' property."},
    {FLB_CONFIG_MAP_STR, "tag_key", FLB_AZURE_KUSTO_DEFAULT_TAG_KEY, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, tag_key),
     "The key name of tag. If 'include_tag_key' is false, "
     "This property is ignored"},
    {FLB_CONFIG_MAP_BOOL, "include_time_key", "true", 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, include_time_key),
     "If enabled, time is appended to output. "
     "The key name is used 'time_key' property."},
    {FLB_CONFIG_MAP_STR, "time_key", FLB_AZURE_KUSTO_DEFAULT_TIME_KEY, 0, FLB_TRUE,
     offsetof(struct flb_azure_kusto, time_key),
     "The key name of the time. If 'include_time_key' is false, "
     "This property is ignored"},
    /* EOF */
    {0}};

struct flb_output_plugin out_azure_kusto_plugin = {
    .name = "azure_kusto",
    .description = "Send events to Kusto (Azure Data Explorer)",
    .cb_init = cb_azure_kusto_init,
    .cb_flush = cb_azure_kusto_flush,
    .cb_exit = cb_azure_kusto_exit,
    .config_map = config_map,
    /* Plugin flags */
    .flags = FLB_OUTPUT_NET | FLB_IO_TLS,
};
