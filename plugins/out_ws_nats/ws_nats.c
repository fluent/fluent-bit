/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_sha512.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include "ws_nats.h"
#include "ws_nats_conf.h"
struct flb_output_plugin out_ws_nats_plugin;

#define SECURED_BY "Fluent Bit"


static int flb_ws_handshake(struct flb_upstream_conn *u_conn,
                                    struct flb_out_ws_nats *ctx)
{
    int ret;
    size_t bytes_sent;
    struct flb_http_client *c;

    if (!u_conn) {
        flb_error("[output_ws_nats] upstream connection error");
        return -1;
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_GET, ctx->uri,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
       flb_upstream_conn_release(u_conn);
       return -1;
    }

    flb_http_buffer_size(c, ctx->buffer_size);
    flb_http_add_header(c, "Upgrade", 7, "websocket", 9);
    flb_http_add_header(c, "Connection", 10, "Upgrade", 7);
    flb_http_add_header(c, "Sec-WebSocket-Key", 17, "dGhlIHNhbXBsZSBub25jZQ==", 24);
    flb_http_add_header(c, "Sec-WebSocket-Version", 21, "13", 2);

    /* Perform request*/
    ret = flb_http_do(c, &bytes_sent);

    if (ret != 0 || c->resp.status != 101) {
        if (c->resp.payload_size > 0) {
            flb_debug("[out_ws_nats] Websocket Server Response\n%s",
                c->resp.payload);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        flb_debug("[out_ws_nats] Http Get Operation ret = %i, http resp = %i", ret, c->resp.status);
        return -1;
    }
    flb_http_client_destroy(c);
    return 0;
}

static void flb_ws_mask(char *data, int len, char *mask)
{
    int i;
    for (i=0;i<len;++i) {
        *(data+i) ^= *(mask+(i%4));
    }
}

static int flb_ws_sendDataFrameHeader(struct flb_upstream_conn *u_conn,
                                      struct flb_out_ws_nats *ctx, const void *data, size_t bytes)
{
    int ret = -1;
    char* data_frame_head;
    size_t bytes_sent;
    int data_frame_head_len = 0;
    //TODO use random function to generate masking_key
    char masking_key[4] = {0x12, 0x34, 0x56, 0x78};
    unsigned long long payloadSize = bytes;

    flb_ws_mask((char *)data, payloadSize, masking_key);
    if (payloadSize < 126) {
        data_frame_head = (char *)flb_malloc(6);
        if (!data_frame_head) {
            flb_errno();
            return -1;
        }
        data_frame_head[0] = 0x81;
        data_frame_head[1] = (payloadSize & 0xff) | 0x80;
        data_frame_head[2] = masking_key[0];
        data_frame_head[3] = masking_key[1];
        data_frame_head[4] = masking_key[2];
        data_frame_head[5] = masking_key[3];
        data_frame_head_len = 6;
    }
    else if (payloadSize < 65536) {
        data_frame_head = (char *)flb_malloc(8);
        if (!data_frame_head) {
            flb_errno();
            return -1;
        }
        data_frame_head[0] = 0x81;
        data_frame_head[1] = 126 | 0x80;
        data_frame_head[2] = (payloadSize >> 8) & 0xff;
        data_frame_head[3] = (payloadSize >> 0) & 0xff;
        data_frame_head[4] = masking_key[0];
        data_frame_head[5] = masking_key[1];
        data_frame_head[6] = masking_key[2];
        data_frame_head[7] = masking_key[3];
        data_frame_head_len = 8;
    }
    else {
        data_frame_head = (char *)flb_malloc(14);
        if (!data_frame_head) {
            flb_errno();
            return -1;
        }
        data_frame_head[0] = 0x81;
        data_frame_head[1] = 127 | 0x80;
        data_frame_head[2] = (payloadSize >> 56) & 0xff;
        data_frame_head[3] = (payloadSize >> 48) & 0xff;
        data_frame_head[4] = (payloadSize >> 40) & 0xff;
        data_frame_head[5] = (payloadSize >> 32) & 0xff;
        data_frame_head[6] = (payloadSize >> 24) & 0xff;
        data_frame_head[7] = (payloadSize >> 16) & 0xff;
        data_frame_head[8] = (payloadSize >>  8) & 0xff;
        data_frame_head[9] = (payloadSize >>  0) & 0xff;
        data_frame_head[10] = masking_key[0];
        data_frame_head[11] = masking_key[1];
        data_frame_head[12] = masking_key[2];
        data_frame_head[13] = masking_key[3];
        data_frame_head_len = 14;
    }
    ret = flb_io_net_write(u_conn, data_frame_head, data_frame_head_len, &bytes_sent);
    if (ret == -1) {
        flb_error("[out_ws_nats] could not write dataframe header");
        goto error;
    }
    flb_free(data_frame_head);
    return 0;

error:
    flb_free(data_frame_head);
    return -1;
}

static int msgpack_to_json(const void *data, size_t bytes,
                           const char *tag, int tag_len,
                           char **out_json, size_t *out_size)
{
    int i;
    int map_size;
    size_t off = 0;
    size_t array_size = 0;
    flb_sds_t out_buf;
    msgpack_object map;
    msgpack_object root;
    msgpack_object m_key;
    msgpack_object m_val;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *obj;
    struct flb_time tm;

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

    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        return -1;
    }

    *out_json = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

static int cb_ws_init(struct flb_output_instance *ins,
                      struct flb_config *config, void *data)
{
    struct flb_out_ws_nats *ctx = NULL;

    ctx = flb_ws_nats_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    ctx->handshake = 1;
    ctx->last_input_timestamp = time(NULL);
    flb_output_set_context(ins, ctx);
    return 0;
}

static int cb_ws_exit(void *data, struct flb_config *config)
{
    struct flb_out_ws_nats *ctx = data;
    flb_ws_conf_destroy(ctx);
    return 0;
}

static void cb_ws_flush(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        struct flb_input_instance *i_ins,
                        void *out_context,
                        struct flb_config *config)
{
    int ret = -1;
    size_t bytes_sent;
    char *connect_proto;
    size_t connect_proto_len;
    size_t json_len;
    flb_sds_t json_msg;
    char *request;
    int req_len;
    flb_sds_t json = NULL;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_out_ws_nats *ctx = out_context;
    time_t now;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);

    if (!u_conn) {
        flb_error("[out_ws_nats] no upstream connections available to %s:%i", u->tcp_host, u->tcp_port);
        ctx->handshake = 1;
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    now = time(NULL);

    flb_debug("[out_ws_nats] interval is  %ld and handshake is %d", now - ctx->last_input_timestamp, ctx->handshake);
    if ((now - ctx->last_input_timestamp > ctx->idle_interval) && (ctx->handshake == 0)) {
        ctx->handshake = 1;
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    ctx->last_input_timestamp = now;

    if (ctx->handshake == 1) {
        /* Handshake with websocket server*/
        flb_info("[out_ws_nats] handshake for ws");
        ret = flb_ws_handshake(u_conn, ctx);
        if (ret == -1) {
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ctx->handshake = 0;

        /* Send CONNECT whenever the handshake has to happen  */
        connect_proto = flb_malloc(sizeof(NATS_CONNECT));
        connect_proto_len = snprintf(connect_proto, sizeof(NATS_CONNECT), NATS_CONNECT);

        ret = flb_ws_sendDataFrameHeader(u_conn, ctx, connect_proto, connect_proto_len);
        if (ret == -1) {
            flb_error("[out_ws_nats] dataFrameHeader sent failed");
            ctx->handshake = 1;
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ret = flb_io_net_write(u_conn, connect_proto, connect_proto_len, &bytes_sent);
        if (ret == -1) {
            flb_error("[out_ws_nats] dataFrameHeader sent failed");
            ctx->handshake = 1;
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    /* Data format process*/
    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(data, bytes,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->json_date_key);

        if (!json) {
            flb_error("[out_ws_nats] error formatting JSON payload");
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    /* Convert original Fluent Bit MsgPack format to JSON */
    ret = msgpack_to_json(data, bytes, tag, tag_len, &json_msg, &json_len);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Compose the NATS Publish request */
    request = flb_malloc(json_len + tag_len + 32);
    if (!request) {
        flb_errno();
        flb_sds_destroy(json_msg);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* PUB <tag> <payload> */
    req_len = snprintf(request, tag_len + 32, "PUB %s %zu\r\n",
                       tag, json_len);

    /* Append JSON message and ending CRLF */
    memcpy(request + req_len, json_msg, json_len);
    req_len += json_len;
    request[req_len++] = '\r';
    request[req_len++] = '\n';
    flb_sds_destroy(json_msg);

    /* Write message header */
    ret = flb_ws_sendDataFrameHeader(u_conn, ctx, request, req_len);
    if (ret == -1) {
        flb_error("[out_ws_nats] dataFrameHeader sent failed");
        ctx->handshake = 1;
        if (json) {
            flb_sds_destroy(json);
        }
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Write message body*/
    if (ctx->out_format == FLB_PACK_JSON_FORMAT_NONE) {
        ret = flb_io_net_write(u_conn, request, req_len, &bytes_sent);
    }
    else {
        ret = flb_io_net_write(u_conn, request, req_len, &bytes_sent);
        flb_sds_destroy(json);
    }
    if (ret == -1) {
        ctx->handshake = 1;
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Release the connection */
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_ws_nats, uri),
     "Specify an optional URI for the target web socket server, e.g: /something"
    },
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Set desired payload format: json, json_stream, json_lines, gelf or msgpack"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_ws_nats_plugin = {
    .name         = "ws_nats",
    .description  = "NATS Websocket",
    .cb_init      = cb_ws_init,
    .cb_flush     = cb_ws_flush,
    .cb_exit      = cb_ws_exit,
    .config_map   = config_map,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
