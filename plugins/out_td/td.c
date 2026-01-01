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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include "td.h"
#include "td_http.h"
#include "td_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Treasure Data cloud service.
 *
 * This function returns a new msgpack buffer and store the bytes length
 * in the out_size variable.
 */
static char *td_format(struct flb_td *ctx, const void *data, size_t bytes, int *out_size)
{
    int i;
    int ret;
    int n_size;
    time_t atime;
    char *buf;
    struct msgpack_sbuffer mp_sbuf;
    struct msgpack_packer mp_pck;
    msgpack_object map;
    msgpack_sbuffer *sbuf;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    /* Initialize contexts for new output */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return NULL;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        atime = log_event.timestamp.tm.tv_sec;
        map   = *log_event.body;

        n_size = map.via.map.size + 1;
        msgpack_pack_map(&mp_pck, n_size);
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "time", 4);
        msgpack_pack_int32(&mp_pck, atime);

        for (i = 0; i < n_size - 1; i++) {
            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].key);
            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].val);
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* Create new buffer */
    sbuf = &mp_sbuf;
    *out_size = sbuf->size;
    buf = flb_malloc(sbuf->size);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return buf;
}

static int cb_td_init(struct flb_output_instance *ins, struct flb_config *config,
                      void *data)
{
    struct flb_td *ctx;
    struct flb_upstream *upstream;
    (void) data;

    ctx = td_config_init(ins);
    if (!ctx) {
        flb_plg_warn(ins, "Error reading configuration");
        return -1;
    }

    if (ctx->region == FLB_TD_REGION_US) {
        flb_output_net_default("api.treasuredata.com", 443, ins);
    }
    else if (ctx->region == FLB_TD_REGION_JP) {
        flb_output_net_default("api.treasuredata.co.jp", 443, ins);
    }

    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   FLB_IO_TLS, ins->tls);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }
    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);

    flb_output_set_context(ins, ctx);
    return 0;
}

static void cb_td_flush(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *i_ins,
                        void *out_context,
                        struct flb_config *config)
{
    int ret;
    int bytes_out;
    char *pack;
    size_t b_sent;
    char *body = NULL;
    struct flb_td *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    (void) i_ins;

    /* Convert format */
    pack = td_format(ctx, event_chunk->data, event_chunk->size, &bytes_out);
    if (!pack) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Lookup an available connection context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        flb_free(pack);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose request */
    c = td_http_client(u_conn, pack, bytes_out, &body, ctx, config);
    if (!c) {
        flb_free(pack);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Issue HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* Release Resources */
    flb_free(pack);
    flb_free(body);

    /* Validate HTTP status */
    if (ret == 0) {
        /* We expect a HTTP 200 OK */
        if (c->resp.status != 200) {
            if (c->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "HTTP status %i\n%s",
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_warn(ctx->ins, "HTTP status %i", c->resp.status);
            }
            goto retry;
        }
        else {
            flb_plg_info(ctx->ins, "HTTP status 200 OK");
        }
    }
    else {
        flb_plg_error(ctx->ins, "http_do=%i", ret);
        goto retry;
    }

    /* release */
    flb_upstream_conn_release(u_conn);
    flb_http_client_destroy(c);

    FLB_OUTPUT_RETURN(FLB_OK);

 retry:
    flb_upstream_conn_release(u_conn);
    flb_http_client_destroy(c);

    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int cb_td_exit(void *data, struct flb_config *config)
{
    struct flb_td *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_STR, "API", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_td, api),
      "Set the API key"
    },
    {
      FLB_CONFIG_MAP_STR, "Database", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_td, db_name),
      "Set the Database file"
    },
    {
      FLB_CONFIG_MAP_STR, "Table", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_td, db_table),
      "Set the Database Table"
    },
    {
      FLB_CONFIG_MAP_STR, "Region", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_td, region_str),
      "Set the Region: us or jp"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_td_plugin = {
    .name           = "td",
    .description    = "Treasure Data",
    .cb_init        = cb_td_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_td_flush,
    .cb_exit        = cb_td_exit,
    .config_map     = config_map,
    .flags          = FLB_IO_TLS,
};
