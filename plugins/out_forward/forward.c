/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <msgpack.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>

#include "forward.h"

struct flb_output_plugin out_forward_plugin;

int cb_forward_init(struct flb_output_instance *ins, struct flb_config *config,
                    void *data)
{
    struct flb_out_forward_config *ctx;
    struct flb_upstream *upstream;
    struct flb_uri_field *f_tag = NULL;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_forward_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }

    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup("127.0.0.1");
    }
    if (ins->host.port == 0) {
        ins->host.port = 24224;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   FLB_IO_TCP, NULL);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }
    ctx->u = upstream;
    ctx->tag = FLB_CONFIG_DEFAULT_TAG;
    ctx->tag_len = sizeof(FLB_CONFIG_DEFAULT_TAG) - 1;

    if (ins->host.uri) {
        if (ins->host.uri->count > 0) {
            f_tag = flb_uri_get(ins->host.uri, 0);
            ctx->tag     = f_tag->value;
            ctx->tag_len = f_tag->length;
        }
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

int cb_forward_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_out_forward_config *ctx = data;

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}

void cb_forward_flush(void *data, size_t bytes,
                      char *tag, int tag_len,
                      struct flb_input_instance *i_ins, void *out_context,
                      struct flb_config *config)
{
    int ret = -1;
    int entries = 0;
    size_t off = 0;
    size_t total;
    size_t bytes_sent;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked result;
    struct flb_out_forward_config *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    (void) i_ins;
    (void) config;

    flb_debug("[out_forward] request %lu bytes to flush", bytes);

    /* Initialize packager */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Count number of entries, is there a better way to do this ? */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        entries++;
    }
    flb_debug("[out_fw] %i entries tag='%s' tag_len=%i",
              entries, tag, tag_len);
    msgpack_unpacked_destroy(&result);

    /* Output: root array */
    msgpack_pack_array(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, tag_len);
    msgpack_pack_str_body(&mp_pck, tag, tag_len);
    msgpack_pack_array(&mp_pck, entries);

    /* Get a TCP connection instance */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[out_forward] no upstream connections available");
        msgpack_sbuffer_destroy(&mp_sbuf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Write message header */
    ret = flb_io_net_write(u_conn, mp_sbuf.data, mp_sbuf.size, &bytes_sent);
    if (ret == -1) {
        flb_error("[out_forward] could not write chunk header");
        msgpack_sbuffer_destroy(&mp_sbuf);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    total = ret;

    /* Write body */
    ret = flb_io_net_write(u_conn, data, bytes, &bytes_sent);
    if (ret == -1) {
        flb_error("[out_forward] error writing content body");
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    total += bytes_sent;
    flb_upstream_conn_release(u_conn);
    flb_trace("[out_forward] ended write()=%d bytes", total);

    FLB_OUTPUT_RETURN(FLB_OK);
}

/* Plugin reference */
struct flb_output_plugin out_forward_plugin = {
    .name         = "forward",
    .description  = "Forward (Fluentd protocol)",
    .cb_init      = cb_forward_init,
    .cb_pre_run   = NULL,
    .cb_flush     = cb_forward_flush,
    .cb_exit      = cb_forward_exit,
    .flags        = FLB_OUTPUT_NET,
};
