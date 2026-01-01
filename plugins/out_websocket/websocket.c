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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include "websocket.h"
#include "websocket_conf.h"
struct flb_output_plugin out_websocket_plugin;

#define SECURED_BY "Fluent Bit"


static int flb_ws_handshake(struct flb_connection *u_conn,
                                    struct flb_out_ws *ctx)
{
    int ret;
    size_t bytes_sent;
    struct flb_http_client *c;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;

    if (!u_conn) {
        flb_error("[output_ws] upstream connection error");
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

    /* Append additional headers from configuration */
    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    /* Perform request*/
    ret = flb_http_do(c, &bytes_sent);

    if (ret != 0 || c->resp.status != 101) {
        if (c->resp.payload_size > 0) {
            flb_debug("[output_ws] Websocket Server Response\n%s",
                c->resp.payload);
        }
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        flb_debug("[out_ws] Http Get Operation ret = %i, http resp = %i", ret, c->resp.status);
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

static int flb_ws_sendDataFrameHeader(struct flb_connection *u_conn,
                                      struct flb_out_ws *ctx, const void *data, size_t bytes)
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
        data_frame_head[1] = (unsigned char) (126 | 0x80);
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
        data_frame_head[1] = (unsigned char) (127 | 0x80);
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
        flb_error("[out_ws] could not write dataframe header");
        goto error;
    }
    flb_free(data_frame_head);
    return 0;

error:
    flb_free(data_frame_head);
    return -1;
}

static int cb_ws_init(struct flb_output_instance *ins,
                      struct flb_config *config, void *data)
{
    struct flb_out_ws *ctx = NULL;

    ctx = flb_ws_conf_create(ins, config);
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
    struct flb_out_ws *ctx = data;
    flb_ws_conf_destroy(ctx);
    return 0;
}

static void cb_ws_flush(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *i_ins,
                        void *out_context,
                        struct flb_config *config)
{
    int ret = -1;
    size_t bytes_sent;
    flb_sds_t json = NULL;
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_out_ws *ctx = out_context;
    time_t now;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);

    if (!u_conn) {
        flb_error("[out_ws] no upstream connections available to %s:%i", u->tcp_host, u->tcp_port);
        ctx->handshake = 1;
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    now = time(NULL);

    //TODO how to determine the interval? conn disconnet is about 30 sec, so we set 20 ssecnds here.
    flb_debug("[out_ws] interval is  %ld and handshake is %d", now - ctx->last_input_timestamp, ctx->handshake);
    if ((now - ctx->last_input_timestamp > ctx->idle_interval) && (ctx->handshake == 0)) {
        ctx->handshake = 1;
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    ctx->last_input_timestamp = now;

    if (ctx->handshake == 1) {
        /* Handshake with websocket server*/
        flb_info("[out_ws] handshake for ws");
        ret = flb_ws_handshake(u_conn, ctx);
        if (ret == -1) {
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        ctx->handshake = 0;
    }

    /* Data format process*/
    if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
        json = flb_pack_msgpack_to_json_format(event_chunk->data,
                                               event_chunk->size,
                                               ctx->out_format,
                                               ctx->json_date_format,
                                               ctx->json_date_key,
                                               config->json_escape_unicode);

        if (!json) {
            flb_error("[out_ws] error formatting JSON payload");
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    /* Write message header */
    if (ctx->out_format == FLB_PACK_JSON_FORMAT_NONE) {
        ret = flb_ws_sendDataFrameHeader(u_conn, ctx,
                                         event_chunk->data,
                                         event_chunk->size);
    }
    else {
        ret = flb_ws_sendDataFrameHeader(u_conn, ctx, json, flb_sds_len(json));
    }

    if (ret == -1) {
        flb_error("[out_ws] dataFrameHeader sent failed");
        ctx->handshake = 1;
        if (json) {
            flb_sds_destroy(json);
        }
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Write message body*/
    if (ctx->out_format == FLB_PACK_JSON_FORMAT_NONE) {
        ret = flb_io_net_write(u_conn,
                               event_chunk->data,
                               event_chunk->size,
                               &bytes_sent);
    }
    else {
        ret = flb_io_net_write(u_conn, json, flb_sds_len(json), &bytes_sent);
        flb_sds_destroy(json);
    }

    //flb_info("[out_ws] sendDataFrame number of bytes sent = %i", ret);
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
     0, FLB_TRUE, offsetof(struct flb_out_ws, uri),
     "Specify an optional URI for the target web socket server, e.g: /something"
    },
    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Set desired payload format: json, json_stream, json_lines, gelf or msgpack"
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_format", "double",
     0, FLB_FALSE, 0,
     "Specify the format of the date"
    },
    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_out_ws, json_date_key),
     "Specify the name of the date field in output"
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_out_ws, headers),
     "Add a HTTP header key/value pair to the initial HTTP request. Multiple headers can be set"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_websocket_plugin = {
    .name         = "websocket",
    .description  = "Websocket",
    .cb_init      = cb_ws_init,
    .cb_flush     = cb_ws_flush,
    .cb_exit      = cb_ws_exit,
    .config_map   = config_map,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
