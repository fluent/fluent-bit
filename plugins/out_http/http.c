/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_gzip.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "http.h"
#include "http_conf.h"

#include <fluent-bit/flb_callback.h>

static int cb_http_init(struct flb_output_instance *ins,
                        struct flb_config *config, void *data)
{
    struct flb_out_http *ctx = NULL;
    (void) data;

    ctx = flb_http_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    return 0;
}

static int http_post(struct flb_out_http *ctx,
                     const void *body, size_t body_len,
                     const char *tag, int tag_len)
{
    int ret;
    int out_ret = FLB_OK;
    int compressed = FLB_FALSE;
    size_t b_sent;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        return FLB_RETRY;
    }

    /* Map payload */
    payload_buf = (void *) body;
    payload_size = body_len;

    /* Should we compress the payload ? */
    if (ctx->compress_gzip == FLB_TRUE) {
        ret = flb_gzip_compress((void *) body, body_len,
                                &payload_buf, &payload_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "cannot gzip payload, disabling compression");
        }
        else {
            compressed = FLB_TRUE;
        }
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        payload_buf, payload_size,
                        ctx->host, ctx->port,
                        ctx->proxy, 0);

    /*
     * Direct assignment of the callback context to the HTTP client context.
     * This needs to be improved through a more clean API.
     */
    c->cb_ctx = ctx->ins->callback;

    /* Append headers */
    if ((ctx->out_format == FLB_PACK_JSON_FORMAT_JSON) ||
        (ctx->out_format == FLB_PACK_JSON_FORMAT_STREAM) ||
        (ctx->out_format == FLB_PACK_JSON_FORMAT_LINES) ||
        (ctx->out_format == FLB_HTTP_OUT_GELF)) {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_JSON,
                            sizeof(FLB_HTTP_MIME_JSON) - 1);
    }
    else {
        flb_http_add_header(c,
                            FLB_HTTP_CONTENT_TYPE,
                            sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                            FLB_HTTP_MIME_MSGPACK,
                            sizeof(FLB_HTTP_MIME_MSGPACK) - 1);
    }

    if (ctx->header_tag) {
        flb_http_add_header(c,
                            ctx->header_tag,
                            flb_sds_len(ctx->header_tag),
                            tag, tag_len);
    }

    /* Content Encoding: gzip */
    if (compressed == FLB_TRUE) {
        flb_http_set_content_encoding_gzip(c);
    }

    /* Basic Auth headers */
    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    ret = flb_http_do(c, &b_sent);
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
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                          ctx->host, ctx->port, c->resp.status);
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                             ctx->host, ctx->port,
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->host, ctx->port,
                             c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->host, ctx->port, ret);
        out_ret = FLB_RETRY;
    }

    /*
     * If the payload buffer is different than incoming records in body, means
     * we generated a different payload and must be freed.
     */
    if (payload_buf != body) {
        flb_free(payload_buf);
    }

    /* Destroy HTTP client context */
    flb_http_client_destroy(c);

    /* Release the TCP connection */
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

static int http_gelf(struct flb_out_http *ctx,
                     const char *data, uint64_t bytes,
                     const char *tag, int tag_len)
{
    flb_sds_t s;
    flb_sds_t tmp = NULL;
    msgpack_unpacked result;
    size_t off = 0;
    size_t size = 0;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    struct flb_time tm;
    int ret;

    size = bytes * 1.5;

    /* Allocate buffer for our new payload */
    s = flb_sds_create_size(size);
    if (!s) {
        return FLB_RETRY;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) ==
           MSGPACK_UNPACK_SUCCESS) {

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map = root.via.array.ptr[1];

        tmp = flb_msgpack_to_gelf(&s, &map, &tm, &(ctx->gelf_fields));
        if (!tmp) {
            flb_plg_error(ctx->ins, "error encoding to GELF");
            flb_sds_destroy(s);
            msgpack_unpacked_destroy(&result);
            return FLB_ERROR;
        }

        /* Append new line */
        tmp = flb_sds_cat(s, "\n", 1);
        if (!tmp) {
            flb_plg_error(ctx->ins, "error concatenating records");
            flb_sds_destroy(s);
            msgpack_unpacked_destroy(&result);
            return FLB_RETRY;
        }
        s = tmp;
    }

    ret = http_post(ctx, s, flb_sds_len(s), tag, tag_len);
    flb_sds_destroy(s);
    msgpack_unpacked_destroy(&result);

    return ret;
}

static void cb_http_flush(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret = FLB_ERROR;
    flb_sds_t json;
    struct flb_out_http *ctx = out_context;
    (void) i_ins;

    if ((ctx->out_format == FLB_PACK_JSON_FORMAT_JSON) ||
        (ctx->out_format == FLB_PACK_JSON_FORMAT_STREAM) ||
        (ctx->out_format == FLB_PACK_JSON_FORMAT_LINES)) {

        json = flb_pack_msgpack_to_json_format(data, bytes,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->json_date_key);
        if (json != NULL) {
            ret = http_post(ctx, json, flb_sds_len(json), tag, tag_len);
            flb_sds_destroy(json);
        }
    }
    else if (ctx->out_format == FLB_HTTP_OUT_GELF) {
        ret = http_gelf(ctx, data, bytes, tag, tag_len);
    }
    else {
        ret = http_post(ctx, data, bytes, tag, tag_len);
    }

    FLB_OUTPUT_RETURN(ret);
}

static int cb_http_exit(void *data, struct flb_config *config)
{
    struct flb_out_http *ctx = data;

    flb_http_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "proxy", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, http_user),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_out_http, http_passwd),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "header_tag", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, header_tag),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_out_http, json_date_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_out_http, headers),
     NULL,
    },
    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, uri),
     NULL,
    },

    /* Gelf Properties */
    {
     FLB_CONFIG_MAP_STR, "gelf_timestamp_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.timestamp_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_host_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.host_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_short_message_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.short_message_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_full_message_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.full_message_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "gelf_level_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_http, gelf_fields.level_key),
     NULL
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_http_plugin = {
    .name        = "http",
    .description = "HTTP Output",
    .cb_init     = cb_http_init,
    .cb_pre_run  = NULL,
    .cb_flush    = cb_http_flush,
    .cb_exit     = cb_http_exit,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
