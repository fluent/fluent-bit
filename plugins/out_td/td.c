/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include "td.h"
#include "td_http.h"
#include "td_config.h"

struct flb_output_plugin out_td_plugin;

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Treasure Data cloud service.
 *
 * This function returns a new msgpack buffer and store the bytes length
 * in the out_size variable.
 */
static char *td_format(void *data, size_t bytes, int *out_size)
{
    int i;
    int ret;
    int n_size;
    size_t off = 0;
    time_t atime;
    char *buf;
    struct msgpack_sbuffer mp_sbuf;
    struct msgpack_packer mp_pck;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_sbuffer *sbuf;
    msgpack_object *obj;
    struct flb_time tm;

    /* Initialize contexts for new output */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);

    /* Perform some format validation */
    ret = msgpack_unpack_next(&result, data, bytes, &off);
    if (ret == MSGPACK_UNPACK_CONTINUE) {
        return NULL;
    }

    /* We 'should' get an array */
    if (result.data.type != MSGPACK_OBJECT_ARRAY) {
        /*
         * If we got a different format, we assume the caller knows what he is
         * doing, we just duplicate the content in a new buffer and cleanup.
         */
        buf = flb_malloc(bytes);
        if (!buf) {
            return NULL;
        }

        memcpy(buf, data, bytes);
        *out_size = bytes;
        return buf;
    }

    root = result.data;
    if (root.via.array.size == 0) {
        return NULL;
    }

    off = 0;
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);

        atime = tm.tm.tv_sec;
        map   = root.via.array.ptr[1];

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
    msgpack_unpacked_destroy(&result);

    /* Create new buffer */
    sbuf = &mp_sbuf;
    *out_size = sbuf->size;
    buf = flb_malloc(sbuf->size);
    if (!buf) {
        return NULL;
    }

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return buf;
}

int cb_td_init(struct flb_output_instance *ins, struct flb_config *config,
               void *data)
{
    struct flb_out_td_config *ctx;
    struct flb_upstream *upstream;
    (void) data;

    ctx = td_config_init(ins);
    if (!ctx) {
        flb_warn("[out_td] Error reading configuration");
        return -1;
    }

    if (ctx->region == FLB_TD_REGION_US) {
        ins->host.name = flb_strdup("api.treasuredata.com");
    }
    else if (ctx->region == FLB_TD_REGION_JP) {
        ins->host.name = flb_strdup("api.treasuredata.co.jp");
    }
    ins->host.port = 443;

    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   FLB_IO_TLS, (void *) &ins->tls);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }
    ctx->u = upstream;

    flb_output_set_context(ins, ctx);
    return 0;
}

static void cb_td_flush(void *data, size_t bytes,
                        char *tag, int tag_len,
                        struct flb_input_instance *i_ins,
                        void *out_context,
                        struct flb_config *config)
{
    int ret;
    int bytes_out;
    char *pack;
    size_t b_sent;
    char *body = NULL;
    struct flb_out_td_config *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    (void) i_ins;
    (void) tag;
    (void) tag_len;

    /* Convert format */
    pack = td_format(data, bytes, &bytes_out);
    if (!pack) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Lookup an available connection context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[out_td] no upstream connections available");
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
                flb_warn("[out_td] HTTP status %i\n%s",
                         c->resp.status, c->resp.payload);
            }
            else {
                flb_warn("[out_td] HTTP status %i", c->resp.status);
            }
            goto retry;
        }
        else {
            flb_info("[out_td] HTTP status 200 OK");
        }
    }
    else {
        flb_error("[out_td] http_do=%i", ret);
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

int cb_td_exit(void *data, struct flb_config *config)
{
    struct flb_out_td_config *ctx = data;

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_td_plugin = {
    .name           = "td",
    .description    = "Treasure Data",
    .cb_init        = cb_td_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_td_flush,
    .cb_exit        = cb_td_exit,
    .flags          = FLB_IO_TLS,
};
