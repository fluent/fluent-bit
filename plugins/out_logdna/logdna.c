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
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "logdna.h"

static inline int primary_key_check(msgpack_object k, char *name, int len)
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

/*
 * This function looks for the following keys and add them to the buffer
 *
 * - level or severity
 * - file
 * - app
 * - meta
 */
static int record_append_primary_keys(struct flb_logdna *ctx,
                                      msgpack_object *map,
                                      msgpack_packer *mp_sbuf)
{
    int i;
    int c = 0;
    msgpack_object *level = NULL;
    msgpack_object *file = NULL;
    msgpack_object *app = NULL;
    msgpack_object *meta = NULL;
    msgpack_object k;
    msgpack_object v;

    for (i = 0; i < map->via.array.size; i++) {
        k = map->via.map.ptr[i].key;
        v = map->via.map.ptr[i].val;

        /* Level - optional */
        if (!level &&
            (primary_key_check(k, "level", 5) == FLB_TRUE ||
             primary_key_check(k, "severity", 8) == FLB_TRUE)) {
            level = &k;
            msgpack_pack_str(mp_sbuf, 5);
            msgpack_pack_str_body(mp_sbuf, "level", 5);
            msgpack_pack_object(mp_sbuf, v);
            c++;
        }

        /* Meta - optional */
        if (!meta && primary_key_check(k, "meta", 4) == FLB_TRUE) {
            meta = &k;
            msgpack_pack_str(mp_sbuf, 4);
            msgpack_pack_str_body(mp_sbuf, "meta", 4);
            msgpack_pack_object(mp_sbuf, v);
            c++;
        }

        /* File */
        if (!file && primary_key_check(k, "file", 4) == FLB_TRUE) {
            file = &k;
            msgpack_pack_str(mp_sbuf, 4);
            msgpack_pack_str_body(mp_sbuf, "file", 4);
            msgpack_pack_object(mp_sbuf, v);
            c++;
        }

        /* App */
        if (primary_key_check(k, "app", 3) == FLB_TRUE) {
            app = &k;
            msgpack_pack_str(mp_sbuf, 3);
            msgpack_pack_str_body(mp_sbuf, "app", 3);
            msgpack_pack_object(mp_sbuf, v);
            c++;
        }
    }

    /* Set the global file name if the record did not provided one */
    if (!file && ctx->file) {
        msgpack_pack_str(mp_sbuf, 4);
        msgpack_pack_str_body(mp_sbuf, "file", 4);
        msgpack_pack_str(mp_sbuf, flb_sds_len(ctx->file));
        msgpack_pack_str_body(mp_sbuf, ctx->file, flb_sds_len(ctx->file));
        c++;
    }


    /* If no application name is set, set the default */
    if (!app) {
        msgpack_pack_str(mp_sbuf, 3);
        msgpack_pack_str_body(mp_sbuf, "app", 3);
        msgpack_pack_str(mp_sbuf, flb_sds_len(ctx->app));
        msgpack_pack_str_body(mp_sbuf, ctx->app, flb_sds_len(ctx->app));
        c++;
    }

    return c;
}

static flb_sds_t logdna_compose_payload(struct flb_logdna *ctx,
                                        const void *data, size_t bytes,
                                        const char *tag, int tag_len,
                                        struct flb_config *config)
{
    int ret;
    int len;
    int total_lines;
    int array_size = 0;
    off_t map_off;
    char *line_json;
    flb_sds_t json;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return NULL;
    }

    /* Count number of records */
    total_lines = flb_mp_count(data, bytes);

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 1);

    msgpack_pack_str(&mp_pck, 5);
    msgpack_pack_str_body(&mp_pck, "lines", 5);

    msgpack_pack_array(&mp_pck, total_lines);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map_off = mp_sbuf.size;

        array_size = 2;
        msgpack_pack_map(&mp_pck, array_size);

        /*
         * Append primary keys found, the return values is the number of appended
         * keys to the record, we use that to adjust the map header size.
         */
        ret = record_append_primary_keys(ctx, log_event.body, &mp_pck);
        array_size += ret;

        /* Timestamp */
        msgpack_pack_str(&mp_pck, 9);
        msgpack_pack_str_body(&mp_pck, "timestamp", 9);
        msgpack_pack_int(&mp_pck, (int) flb_time_to_double(&log_event.timestamp));

        /* Line */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "line", 4);

        line_json = flb_msgpack_to_json_str(1024, log_event.body, config->json_escape_unicode);
        len = strlen(line_json);
        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, line_json, len);
        flb_free(line_json);

        /* Adjust map header size */
        flb_mp_set_map_header_size(mp_sbuf.data + map_off, array_size);
    }

    flb_log_event_decoder_destroy(&log_decoder);

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                       config->json_escape_unicode);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return json;
}

static void logdna_config_destroy(struct flb_logdna *ctx)
{
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->tags_formatted) {
        flb_sds_destroy(ctx->tags_formatted);
    }

    flb_free(ctx);
}

static struct flb_logdna *logdna_config_create(struct flb_output_instance *ins,
                                               struct flb_config *config)
{
    int ret;
    int len = 0;
    char *hostname;
    flb_sds_t tmp;
    flb_sds_t encoded;
    struct mk_list *head;
    struct flb_slist_entry *tag_entry;
    struct flb_logdna *ctx;
    struct flb_upstream *upstream;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_logdna));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        logdna_config_destroy(ctx);
        return NULL;
    }

    /* validate API key */
    if (!ctx->api_key) {
        flb_plg_error(ins, "no `api_key` was set, this is a mandatory property");
        logdna_config_destroy(ctx);
        return NULL;
    }

    /*
     * Tags: this value is a linked list of values created by the config map
     * reader.
     */
    if (ctx->tags) {
        /* For every tag, make sure no empty spaces exists */
        mk_list_foreach(head, ctx->tags) {
            tag_entry = mk_list_entry(head, struct flb_slist_entry, _head);
            len += flb_sds_len(tag_entry->str) + 1;
        }

        /* Compose a full tag for URI request */
        ctx->tags_formatted = flb_sds_create_size(len);
        if (!ctx->tags_formatted) {
            logdna_config_destroy(ctx);
            return NULL;
        }

        mk_list_foreach(head, ctx->tags) {
            tag_entry = mk_list_entry(head, struct flb_slist_entry, _head);

            encoded = flb_uri_encode(tag_entry->str,
                                     flb_sds_len(tag_entry->str));
            tmp = flb_sds_cat(ctx->tags_formatted,
                              encoded, flb_sds_len(encoded));
            ctx->tags_formatted = tmp;
            flb_sds_destroy(encoded);

            if (tag_entry->_head.next != ctx->tags) {
                tmp = flb_sds_cat(ctx->tags_formatted, ",", 1);
                ctx->tags_formatted = tmp;
            }
        }
    }

    /*
     * Hostname: if the hostname was not set manually, try to get it from the
     * environment variable.
     *
     * Note that hostname is populated by a config map, and config maps are
     * immutable so we use an internal variable to do a final composition
     * if required.
     */
    if (!ctx->hostname) {
        tmp = NULL;
        hostname = (char *) flb_env_get(config->env, "HOSTNAME");
        if (hostname) {
            ctx->_hostname = flb_sds_create(hostname);
        }
        else {
            ctx->_hostname = flb_sds_create("unknown");
        }
    }
    else {
        ctx->_hostname = flb_sds_create(ctx->hostname);
    }

    /* Bail if unsuccessful hostname creation */
    if (!ctx->_hostname) {
        flb_free(ctx);
        return NULL;
    }

    /* Create Upstream connection context */
    upstream = flb_upstream_create(config,
                                   ctx->logdna_host,
                                   ctx->logdna_port,
                                   FLB_IO_TLS, ins->tls);
    if (!upstream) {
        flb_free(ctx);
        return NULL;
    }
    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);

    /* Set networking defaults */
    flb_output_net_default(FLB_LOGDNA_HOST, atoi(FLB_LOGDNA_PORT), ins);
    return ctx;
}

static int cb_logdna_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_logdna *ctx;

    ctx = logdna_config_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize configuration");
        return -1;
    }

    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ins, "configured, hostname=%s", ctx->hostname);
    return 0;
}

static void cb_logdna_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    flb_sds_t uri;
    flb_sds_t tmp;
    flb_sds_t payload;
    struct flb_logdna *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    /* Format the data to the expected LogDNA Payload */
    payload = logdna_compose_payload(ctx,
                                     event_chunk->data,
                                     event_chunk->size,
                                     event_chunk->tag,
                                     flb_sds_len(event_chunk->tag),
                                     config);
    if (!payload) {
        flb_plg_error(ctx->ins, "cannot compose request payload");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Lookup an available connection context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        flb_sds_destroy(payload);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose the HTTP URI */
    uri = flb_sds_create_size(256);
    if (!uri) {
        flb_plg_error(ctx->ins, "cannot allocate buffer for URI");
        flb_sds_destroy(payload);
        flb_free(ctx);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    tmp = flb_sds_printf(&uri,
                         "%s?hostname=%s&mac=%s&ip=%s&now=%lu&tags=%s",
                         ctx->logdna_endpoint,
                         ctx->_hostname,
                         ctx->mac_addr,
                         ctx->ip_addr,
                         time(NULL),
                         ctx->tags_formatted);
    if (!tmp) {
        flb_plg_error(ctx->ins, "error formatting URI");
        flb_sds_destroy(payload);
        flb_free(ctx);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, uri,
                        payload, flb_sds_len(payload),
                        ctx->logdna_host, ctx->logdna_port,
                        NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_sds_destroy(uri);
        flb_sds_destroy(payload);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Set callback context to the HTTP client context */
    flb_http_set_callback_context(c, ctx->ins->callback);

    /* User Agent */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* Add Content-Type header */
    flb_http_add_header(c,
                        FLB_LOGDNA_CT, sizeof(FLB_LOGDNA_CT) - 1,
                        FLB_LOGDNA_CT_JSON, sizeof(FLB_LOGDNA_CT_JSON) - 1);

    /* Add auth */
    flb_http_basic_auth(c, ctx->api_key, "");

    flb_http_strip_port_from_host(c);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Destroy buffers */
    flb_sds_destroy(uri);
    flb_sds_destroy(payload);

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
                              ctx->logdna_host, ctx->logdna_port, c->resp.status,
                              c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->logdna_host, ctx->logdna_port, c->resp.status);
            }
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                             ctx->logdna_host, ctx->logdna_port,
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->logdna_host, ctx->logdna_port,
                             c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%s (http_do=%i)",
                      FLB_LOGDNA_HOST, FLB_LOGDNA_PORT, ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(out_ret);
}

static int cb_logdna_exit(void *data, struct flb_config *config)
{
    struct flb_logdna *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->_hostname) {
        flb_sds_destroy(ctx->_hostname);
    }
    logdna_config_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "logdna_host", FLB_LOGDNA_HOST,
     0, FLB_TRUE, offsetof(struct flb_logdna, logdna_host),
     "LogDNA Host address"
    },

    {
     FLB_CONFIG_MAP_INT, "logdna_port", FLB_LOGDNA_PORT,
     0, FLB_TRUE, offsetof(struct flb_logdna, logdna_port),
     "LogDNA TCP port"
    },

    {
     FLB_CONFIG_MAP_STR, "logdna_endpoint", FLB_LOGDNA_ENDPOINT,
     0, FLB_TRUE, offsetof(struct flb_logdna, logdna_endpoint),
     "LogDNA endpoint to send logs"
    },

    {
     FLB_CONFIG_MAP_STR, "api_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_logdna, api_key),
     "Logdna API key"
    },

    {
     FLB_CONFIG_MAP_STR, "hostname", NULL,
     0, FLB_TRUE, offsetof(struct flb_logdna, hostname),
     "Local Server or device host name"
    },

    {
     FLB_CONFIG_MAP_STR, "mac", "",
     0, FLB_TRUE, offsetof(struct flb_logdna, mac_addr),
     "MAC address (optional)"
    },

    {
     FLB_CONFIG_MAP_STR, "ip", "",
     0, FLB_TRUE, offsetof(struct flb_logdna, ip_addr),
     "IP address (optional)"
    },

    {
     FLB_CONFIG_MAP_CLIST, "tags", "",
     0, FLB_TRUE, offsetof(struct flb_logdna, tags),
     "Tags (optional)"
    },

    {
     FLB_CONFIG_MAP_STR, "file", NULL,
     0, FLB_TRUE, offsetof(struct flb_logdna, file),
     "Name of the monitored file (optional)"
    },

    {
     FLB_CONFIG_MAP_STR, "app", "Fluent Bit",
     0, FLB_TRUE, offsetof(struct flb_logdna, app),
     "Name of the application generating the data (optional)"
    },

    /* EOF */
    {0}

};

/* Plugin reference */
struct flb_output_plugin out_logdna_plugin = {
    .name        = "logdna",
    .description = "LogDNA",
    .cb_init     = cb_logdna_init,
    .cb_flush    = cb_logdna_flush,
    .cb_exit     = cb_logdna_exit,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_NET | FLB_IO_TLS,
};
