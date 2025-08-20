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
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "newrelic.h"

static inline uint64_t time_to_milliseconds(struct flb_time *tms)
{
    return ((tms->tm.tv_sec * 1000) + (tms->tm.tv_nsec / 1000000));
}

static inline int key_matches(msgpack_object k, char *name, int len)
{
    if (k.type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }

    if (k.via.str.size != len) {
        return FLB_FALSE;
    }

    if (memcmp(k.via.str.ptr, name, len) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int package_record(struct flb_time *ts, msgpack_object *map,
                          msgpack_packer *mp_pck)
{
    int i;
    int map_size = 0;
    uint64_t timestamp_ms;
    int log = -1;
    int message = -1;
    msgpack_object k;
    msgpack_object v;

    /* Check if 'message' or 'log' key exists in the record */
    for (i = 0; i < map->via.map.size; i++) {
        k = map->via.map.ptr[i].key;

        if (message == -1 && key_matches(k, "message", 7) == FLB_TRUE) {
            message = i;
            continue;
        }

        /* If we find 'log', just stop iterating */
        if (log == -1 && key_matches(k, "log", 3) == FLB_TRUE) {
            log = i;
            break;
        }
    }

    /* The log map contains at least 2 entries: 'timestamp' and 'attributes' */
    map_size = 2;

    /* If 'log' or 'message' are set, we add the 'message' key */
    if (log >= 0 || message >= 0) {
        map_size++;
    }

    /* Package the final record */
    msgpack_pack_map(mp_pck, map_size);

    /* Convert timestamp to milliseconds */
    timestamp_ms = time_to_milliseconds(ts);

    /* Pack timestamp */
    msgpack_pack_str(mp_pck, 9);
    msgpack_pack_str_body(mp_pck, "timestamp", 9);
    msgpack_pack_uint64(mp_pck, timestamp_ms);

    /* Keep 'log' over 'message' */
    if (log >= 0) {
        message = -1;
        msgpack_pack_str(mp_pck, 7);
        msgpack_pack_str_body(mp_pck, "message", 7);
        v = map->via.map.ptr[log].val;
        msgpack_pack_object(mp_pck, v);
    }
    else if (message >= 0) {
        msgpack_pack_str(mp_pck, 7);
        msgpack_pack_str_body(mp_pck, "message", 7);
        v = map->via.map.ptr[message].val;
        msgpack_pack_object(mp_pck, v);
    }

    /* Adjust attributes map size */
    map_size = map->via.map.size;
    if (log >= 0 || message >= 0) {
        map_size--;
    }

    msgpack_pack_str(mp_pck, 10);
    msgpack_pack_str_body(mp_pck, "attributes", 10);
    msgpack_pack_map(mp_pck, map_size);

    /* Pack remaining attributes */
    for (i = 0; i < map->via.map.size; i++) {
        k = map->via.map.ptr[i].key;
        v = map->via.map.ptr[i].val;

        if (log >= 0 && key_matches(k, "log", 3) == FLB_TRUE) {
            continue;
        }

        if (message >= 0 && key_matches(k, "message", 7) == FLB_TRUE) {
            continue;
        }

        msgpack_pack_object(mp_pck, k);
        msgpack_pack_object(mp_pck, v);
    }

    return 0;
}

static flb_sds_t newrelic_compose_payload(struct flb_newrelic *ctx,
                                          const void *data, size_t bytes,
                                          struct flb_config *config)
{
    int total_records;
    flb_sds_t json;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    /*
     * Following the New Relic Fluentd implementation, this is the
     * suggested structure for our payload:
     *
     *     payload = {[
     *       'common' => {
     *         'attributes' => {
     *           'plugin' => {
     *             'type' => 'fluentd',
     *             'version' => NewrelicFluentdOutput::VERSION,
     *           }
     *         }
     *       },
     *       'logs' => []
     *     ]}
     */

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return NULL;
    }

    /* Count number of records */
    total_records = flb_mp_count(data, bytes);

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* The New Relic MELT API format is wrapped in an array */
    msgpack_pack_array(&mp_pck, 1);

    /* Map for 'common' and 'logs' */
    msgpack_pack_map(&mp_pck, 2);

    /* 'common' map */
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "common", 6);
    msgpack_pack_map(&mp_pck, 1);

    /* common['attributes'] */
    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "attributes", 10);
    msgpack_pack_map(&mp_pck, 1);

    /* common['attributes']['plugin'] */
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "plugin", 6);
    msgpack_pack_map(&mp_pck, 2);

    /* common['attributes']['plugin']['type'] = 'Fluent Bit' */
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "type", 4);
    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "Fluent Bit", 10);

    /* common['attributes']['plugin']['version'] = 'FLB_VERSION_STR' */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "version", 7);
    msgpack_pack_str(&mp_pck, sizeof(FLB_VERSION_STR) - 1);
    msgpack_pack_str_body(&mp_pck, FLB_VERSION_STR, sizeof(FLB_VERSION_STR) - 1);

    /* 'logs' array */
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "logs", 4);
    msgpack_pack_array(&mp_pck, total_records);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        /* Package the record */
        package_record(&log_event.timestamp, log_event.body, &mp_pck);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                       config->json_escape_unicode);

    msgpack_sbuffer_destroy(&mp_sbuf);

    return json;
}

static void newrelic_config_destroy(struct flb_newrelic *ctx)
{
    flb_free(ctx->nr_protocol);
    flb_free(ctx->nr_host);
    flb_free(ctx->nr_uri);

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    flb_free(ctx);
}

static struct flb_newrelic *newrelic_config_create(struct flb_output_instance *ins,
                                                   struct flb_config *config)
{
    int ret;
    char *port = NULL;
    struct flb_newrelic *ctx;
    struct flb_upstream *upstream;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_newrelic));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        newrelic_config_destroy(ctx);
        return NULL;
    }

    /* At least we need one of api_key or license_key */
    if (!ctx->api_key && !ctx->license_key) {
        flb_plg_error(ctx->ins, "no 'api_key' or 'license_key' was configured");
        newrelic_config_destroy(ctx);
        return NULL;
    }

    /* Parse Base URL */
    ret = flb_utils_url_split(ctx->base_uri,
                              &ctx->nr_protocol,
                              &ctx->nr_host,
                              &port,
                              &ctx->nr_uri);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error parsing base_uri '%s'", ctx->base_uri);
        newrelic_config_destroy(ctx);
        return NULL;
    }
    ctx->nr_port = atoi(port);
    flb_free(port);

    if (strcasecmp(ctx->compress, "gzip") == 0) {
        ctx->compress_gzip = FLB_TRUE;
    }
    else if (flb_utils_bool(ctx->compress) == FLB_FALSE) {
        ctx->compress_gzip = FLB_FALSE;
    }
    else {
        flb_plg_warn(ctx->ins,
                     "unknown compress encoding value '%s', "
                     "payload compression has been disabled",
                     ctx->compress);
        ctx->compress_gzip = FLB_FALSE;
    }

    /* Create Upstream connection context */
    upstream = flb_upstream_create(config,
                                   ctx->nr_host,
                                   ctx->nr_port,
                                   FLB_IO_TLS, ins->tls);
    if (!upstream) {
        flb_free(ctx);
        return NULL;
    }
    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

static int cb_newrelic_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data)
{
    struct flb_newrelic *ctx;

    /* Create plugin context */
    ctx = newrelic_config_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize configuration");
        return -1;
    }

    /* Register context with plugin instance */
    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ins, "configured, hostname=%s:%i", ctx->nr_host, ctx->nr_port);
    return 0;
}

static void cb_newrelic_flush(struct flb_event_chunk *event_chunk,
                              struct flb_output_flush *out_flush,
                              struct flb_input_instance *i_ins,
                              void *out_context,
                              struct flb_config *config)
{
    int ret;
    int out_ret = FLB_OK;
    int compressed = FLB_FALSE;
    size_t b_sent;
    flb_sds_t payload;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    struct flb_newrelic *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    /* Format the data to the expected Newrelic Payload */
    payload = newrelic_compose_payload(ctx,
                                       event_chunk->data, event_chunk->size,
                                       config);
    if (!payload) {
        flb_plg_error(ctx->ins, "cannot compose request payload");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Map payload */
    payload_buf  = (void *) payload;
    payload_size = flb_sds_len(payload);

    /* Should we compress the payload ? */
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress(payload, flb_sds_len(payload),
                                &payload_buf, &payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        }
        else {
            compressed = FLB_TRUE;
            flb_sds_destroy(payload);
        }
    }

    /* Lookup an available connection context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        if (compressed == FLB_TRUE) {
            flb_free(payload_buf);
        }
        else {
            flb_sds_destroy(payload);
        }
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->nr_uri,
                        payload_buf, payload_size,
                        ctx->nr_host, ctx->nr_port,
                        NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        if (compressed == FLB_TRUE) {
            flb_free(payload_buf);
        }
        else {
            flb_sds_destroy(payload);
        }
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Set callback context to the HTTP client context */
    flb_http_set_callback_context(c, ctx->ins->callback);

    /* User Agent */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* API / License Key */
    if (ctx->license_key) {
        flb_http_add_header(c,
                            "X-License-Key", 13,
                            ctx->license_key, flb_sds_len(ctx->license_key));
    }
    else if (ctx->api_key) {
        flb_http_add_header(c,
                            "X-Insert-Key", 12,
                            ctx->api_key, flb_sds_len(ctx->api_key));
    }

    /* Add Content-Type header */
    flb_http_add_header(c,
                        FLB_NEWRELIC_CT, sizeof(FLB_NEWRELIC_CT) - 1,
                        FLB_NEWRELIC_CT_JSON, sizeof(FLB_NEWRELIC_CT_JSON) - 1);

    /* Encoding */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Destroy buffers */
    if (compressed == FLB_FALSE) {
        flb_sds_destroy(payload);
    }
    else {
        flb_free(payload_buf);
    }

    /* Validate HTTP client return status */
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status < 200 || c->resp.status > 205) {
            if (c->resp.payload) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->nr_host, ctx->nr_port, c->resp.status,
                              c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->nr_host, ctx->nr_port, c->resp.status);
            }
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                             ctx->nr_host, ctx->nr_port,
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->nr_host, ctx->nr_port,
                             c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->nr_host, ctx->nr_port, ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(out_ret);
}

static int cb_newrelic_exit(void *data, struct flb_config *config)
{
    struct flb_newrelic *ctx = data;

    if (!ctx) {
        return 0;
    }

    newrelic_config_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "base_uri", FLB_NEWRELIC_BASE_URI,
     0, FLB_TRUE, offsetof(struct flb_newrelic, base_uri),
     "New Relic Host address"
    },

    {
     FLB_CONFIG_MAP_STR, "api_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_newrelic, api_key),
     "New Relic API Key"
    },

    {
     FLB_CONFIG_MAP_STR, "license_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_newrelic, license_key),
     "New Relic License Key"
    },

    {
     FLB_CONFIG_MAP_STR, "compress", "gzip",
     0, FLB_TRUE, offsetof(struct flb_newrelic, compress),
     "Set payload compression mechanism",
    },

    /* EOF */
    {0}

};

/* Plugin reference */
struct flb_output_plugin out_nrlogs_plugin = {
    .name        = "nrlogs",
    .description = "New Relic",
    .cb_init     = cb_newrelic_init,
    .cb_flush    = cb_newrelic_flush,
    .cb_exit     = cb_newrelic_exit,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_NET | FLB_IO_TLS,
};
