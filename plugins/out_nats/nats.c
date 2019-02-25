/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>

#include <stdio.h>
#include <msgpack.h>

#include "nats.h"

int cb_nats_init(struct flb_output_instance *ins, struct flb_config *config,
                   void *data)
{
    int io_flags;
    struct flb_upstream *upstream;
    struct flb_out_nats_config *ctx;

    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup("127.0.0.1");
    }
    if (ins->host.port == 0) {
        ins->host.port = 4222;
    }

    /* Allocate plugin context */
    ctx = flb_malloc(sizeof(struct flb_out_nats_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }

    io_flags = FLB_IO_TCP;
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   FLB_IO_TCP,
                                   NULL);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }
    ctx->u   = upstream;
    ctx->ins = ins;
    flb_output_set_context(ins, ctx);

    return 0;
}

static int msgpack_to_json(void *data, size_t bytes,
                           char *tag, int tag_len,
                           char **out_json, size_t *out_size)
{
    int i;
    int ret;
    int map_size;
    size_t off = 0;
    size_t array_size = 0;
    msgpack_object map;
    msgpack_object root;
    msgpack_object m_key;
    msgpack_object m_val;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *obj;
    struct flb_time tm;
    char *json_buf;
    size_t json_size;

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);
    off = 0;

    /* Convert MsgPack to JSON */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, array_size);

    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        root = result.data;

        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map    = root.via.array.ptr[1];
        map_size = map.via.map.size;

        msgpack_pack_array(&mp_pck, 2);
        msgpack_pack_double(&mp_pck, flb_time_to_double(&tm));

        msgpack_pack_map(&mp_pck, map_size + 1);
        msgpack_pack_str(&mp_pck, 3);
        msgpack_pack_str_body(&mp_pck, "tag", 3);
        msgpack_pack_str(&mp_pck, tag_len);
        msgpack_pack_str_body(&mp_pck, tag, tag_len);

        for (i = 0; i < map_size; i++) {
            m_key = map.via.map.ptr[i].key;
            m_val = map.via.map.ptr[i].val;

            msgpack_pack_object(&mp_pck, m_key);
            msgpack_pack_object(&mp_pck, m_val);
        }
    }
    msgpack_unpacked_destroy(&result);

    ret = flb_msgpack_raw_to_json_str(mp_sbuf.data, mp_sbuf.size,
                                      &json_buf, &json_size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (ret != 0) {
        return -1;
    }

    *out_json = json_buf;
    *out_size = json_size;

    return 0;
}

void cb_nats_flush(void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_input_instance *i_ins,
                   void *out_context,
                   struct flb_config *config)
{
    int ret;
    size_t bytes_sent;
    size_t json_len;
    char *json_msg;
    char *request;
    int req_len;
    struct flb_out_nats_config *ctx = out_context;
    struct flb_upstream_conn *u_conn;

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[out_nats] no upstream connections available");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Before to flush the content check if we need to start the handshake */
    ret = flb_io_net_write(u_conn,
                           NATS_CONNECT,
                           sizeof(NATS_CONNECT) - 1,
                           &bytes_sent);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert original Fluent Bit MsgPack format to JSON */
    ret = msgpack_to_json(data, bytes, tag, tag_len, &json_msg, &json_len);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Compose the NATS Publish request */
    request = flb_malloc(json_len + tag_len + 32);
    req_len = snprintf(request, tag_len + 32, "PUB %s %zu\r\n",
                       tag, json_len);

    /* Append JSON message and ending CRLF */
    memcpy(request + req_len, json_msg, json_len);
    req_len += json_len;
    request[req_len++] = '\r';
    request[req_len++] = '\n';
    flb_free(json_msg);

    ret = flb_io_net_write(u_conn, request, req_len, &bytes_sent);
    if (ret == -1) {
        perror("write");
        flb_free(request);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_free(request);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_nats_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_out_nats_config *ctx = data;

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}

struct flb_output_plugin out_nats_plugin = {
    .name         = "nats",
    .description  = "NATS Server",
    .cb_init      = cb_nats_init,
    .cb_flush     = cb_nats_flush,
    .cb_exit      = cb_nats_exit,
    .flags        = FLB_OUTPUT_NET,
};
