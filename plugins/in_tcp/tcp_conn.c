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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>

#include "tcp.h"
#include "tcp_conn.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int process_pack(struct tcp_conn *conn,
                               char *pack, size_t size)
{
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object entry;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* First pack the results, iterate concatenated messages */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        entry = result.data;

        msgpack_pack_array(&mp_pck, 2);
        flb_pack_time_now(&mp_pck);

        if (entry.type == MSGPACK_OBJECT_MAP) {
            msgpack_pack_object(&mp_pck, entry);
        }
        else if (entry.type == MSGPACK_OBJECT_ARRAY) {
            msgpack_pack_map(&mp_pck, 1);
            msgpack_pack_str(&mp_pck, 3);
            msgpack_pack_str_body(&mp_pck, "msg", 3);
            msgpack_pack_object(&mp_pck, entry);
        }
        else {
            flb_plg_debug(conn->ins, "record is not a JSON map or array");
            msgpack_unpacked_destroy(&result);
            msgpack_sbuffer_destroy(&mp_sbuf);
            return -1;
        }
    }

    msgpack_unpacked_destroy(&result);

    flb_input_chunk_append_raw(conn->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

/* Process a JSON payload, return the number of processed bytes */
static ssize_t parse_payload_json(struct tcp_conn *conn)
{
    int ret;
    int out_size;
    char *pack;

    ret = flb_pack_json_state(conn->buf_data, conn->buf_len,
                              &pack, &out_size, &conn->pack_state);
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_debug(conn->ins, "JSON incomplete, waiting for more data...");
        return 0;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(conn->ins, "invalid JSON message, skipping");
        conn->buf_len = 0;
        conn->pack_state.multiple = FLB_TRUE;
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    process_pack(conn, pack, out_size);
    flb_free(pack);

    return conn->pack_state.last_byte;
}

/*
 * Process a raw text payload, uses the delimited character to split records,
 * return the number of processed bytes
 */
static ssize_t parse_payload_none(struct tcp_conn *conn)
{
    int len;
    int sep_len;
    size_t consumed = 0;
    char *buf;
    char *s;
    char *separator;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    separator = conn->ctx->separator;
    sep_len = flb_sds_len(conn->ctx->separator);

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    buf = conn->buf_data;

    while ((s = strstr(buf, separator))) {
        len = (s - buf);
        if (len == 0) {
            break;
        }
        else if (len > 0) {
            msgpack_pack_array(&mp_pck, 2);
            flb_pack_time_now(&mp_pck);
            msgpack_pack_map(&mp_pck, 1);
            msgpack_pack_str(&mp_pck, 3);
            msgpack_pack_str_body(&mp_pck, "log", 3);
            msgpack_pack_str(&mp_pck, len);
            msgpack_pack_str_body(&mp_pck, buf, len);
            consumed += len + 1;
            buf += len + sep_len;
        }
        else {
            break;
        }
    }

    flb_input_chunk_append_raw(conn->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return consumed;
}

/* Callback invoked every time an event is triggered for a connection */
int tcp_conn_event(void *data)
{
    int bytes;
    int available;
    int size;
    ssize_t ret_payload = -1;
    char *tmp;
    struct mk_event *event;
    struct tcp_conn *conn = data;
    struct flb_in_tcp_config *ctx = conn->ctx;

    event = &conn->event;
    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->chunk_size > ctx->buffer_size) {
                flb_plg_trace(ctx->ins,
                              "fd=%i incoming data exceed limit (%zu KB)",
                              event->fd, (ctx->buffer_size / 1024));
                tcp_conn_del(conn);
                return -1;
            }

            size = conn->buf_size + ctx->chunk_size;
            tmp = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                flb_errno();
                return -1;
            }
            flb_plg_trace(ctx->ins, "fd=%i buffer realloc %i -> %i",
                          event->fd, conn->buf_size, size);

            conn->buf_data = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len) - 1;
        }

        /* Read data */
        bytes = recv(conn->fd,
                     conn->buf_data + conn->buf_len, available, 0);
        if (bytes <= 0) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            tcp_conn_del(conn);
            return -1;
        }

        flb_plg_trace(ctx->ins, "read()=%i pre_len=%i now_len=%i",
                      bytes, conn->buf_len, conn->buf_len + bytes);
        conn->buf_len += bytes;
        conn->buf_data[conn->buf_len] = '\0';

        /* Strip CR or LF if found at first byte */
        if (conn->buf_data[0] == '\r' || conn->buf_data[0] == '\n') {
            /* Skip message with one byte with CR or LF */
            flb_plg_trace(ctx->ins, "skip one byte message with ASCII code=%i",
                      conn->buf_data[0]);
            consume_bytes(conn->buf_data, 1, conn->buf_len);
            conn->buf_len--;
            conn->buf_data[conn->buf_len] = '\0';
        }

        /* JSON Format handler */
        if (ctx->format == FLB_TCP_FMT_JSON) {
            ret_payload = parse_payload_json(conn);
            if (ret_payload == 0) {
                /* Incomplete JSON message, we need more data */
                return -1;
            }
            else if (ret_payload == -1) {
                flb_pack_state_reset(&conn->pack_state);
                flb_pack_state_init(&conn->pack_state);
                conn->pack_state.multiple = FLB_TRUE;
                return -1;
            }
        }
        else if (ctx->format == FLB_TCP_FMT_NONE) {
            ret_payload = parse_payload_none(conn);
            if (ret_payload == 0) {
                return -1;
            }
            else if (ret_payload == -1) {
                conn->buf_len = 0;
                return -1;
            }
        }

        consume_bytes(conn->buf_data, ret_payload, conn->buf_len);
        conn->buf_len -= ret_payload;
        conn->buf_data[conn->buf_len] = '\0';

        if (ctx->format == FLB_TCP_FMT_JSON) {
            jsmn_init(&conn->pack_state.parser);
            conn->pack_state.tokens_count = 0;
            conn->pack_state.last_byte = 0;
            conn->pack_state.buf_len = 0;
        }

        return bytes;
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        tcp_conn_del(conn);
        return -1;
    }

    return 0;
}

/* Create a new mqtt request instance */
struct tcp_conn *tcp_conn_add(int fd, struct flb_in_tcp_config *ctx)
{
    int ret;
    struct tcp_conn *conn;
    struct mk_event *event;

    conn = flb_malloc(sizeof(struct tcp_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    /* Set data for the event-loop */
    event = &conn->event;
    MK_EVENT_NEW(event);
    event->fd           = fd;
    event->type         = FLB_ENGINE_EV_CUSTOM;
    event->handler      = tcp_conn_event;

    /* Connection info */
    conn->fd      = fd;
    conn->ctx     = ctx;
    conn->buf_len = 0;
    conn->rest    = 0;
    conn->status  = TCP_NEW;

    conn->buf_data = flb_malloc(ctx->chunk_size);
    if (!conn->buf_data) {
        flb_errno();
        flb_socket_close(fd);
        flb_plg_error(ctx->ins, "could not allocate new connection");
        flb_free(conn);
        return NULL;
    }
    conn->buf_size = ctx->chunk_size;
    conn->ins      = ctx->ins;

    /* Initialize JSON parser */
    if (ctx->format == FLB_TCP_FMT_JSON) {
        flb_pack_state_init(&conn->pack_state);
        conn->pack_state.multiple = FLB_TRUE;
    }

    /* Register instance into the event loop */
    ret = mk_event_add(ctx->evl, fd, FLB_ENGINE_EV_CUSTOM, MK_EVENT_READ, conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");
        flb_socket_close(fd);
        flb_free(conn->buf_data);
        flb_free(conn);
        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->connections);

    return conn;
}

int tcp_conn_del(struct tcp_conn *conn)
{
    struct flb_in_tcp_config *ctx;

    ctx = conn->ctx;

    if (ctx->format == FLB_TCP_FMT_JSON) {
        flb_pack_state_reset(&conn->pack_state);
    }
    /* Unregister the file descriptior from the event-loop */
    mk_event_del(ctx->evl, &conn->event);

    /* Release resources */
    mk_list_del(&conn->_head);
    flb_socket_close(conn->fd);
    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}
