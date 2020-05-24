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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>

#include "gelf.h"
#include "gelf_conn.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline void gelf_msgpack_pack_key(struct gelf_conn *conn,
                                 msgpack_packer* mp_pck,
                                 msgpack_object key)
{
    char *key_str = NULL;
    size_t key_str_size = 0;
    if (key.type == MSGPACK_OBJECT_STR) {
        key_str  = (char *) key.via.str.ptr;
        key_str_size = key.via.str.size;
    }
    if (key_str && key_str_size>1 && key_str[0]== '_') {
        flb_plg_trace(conn->ins, "removing leading _ from key '%*.*s'",
                      key_str_size, key_str_size, key_str);
        msgpack_pack_str(mp_pck, key_str_size-1);
        msgpack_pack_str_body(mp_pck, key_str+1, key_str_size-1);
    } else {
        msgpack_pack_object(mp_pck, key);
    }
}

static inline int process_pack(struct gelf_conn *conn,
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
            msgpack_pack_map(&mp_pck, entry.via.map.size);
            for (int i = 0; i < entry.via.map.size; i++) {
                gelf_msgpack_pack_key(conn, &mp_pck, entry.via.map.ptr[i].key);
                msgpack_pack_object(&mp_pck, entry.via.map.ptr[i].val);
            }
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

/* Process a payload, return the number of processed bytes */
static ssize_t parse_json_payload(struct gelf_conn *conn)
{
    int ret;
    int out_size;
    char *pack;
    char *nullbyte;

    /* clear embedded null bytes record separators */
    while ((nullbyte = memchr(conn->buf_data, '\0', conn->buf_len))) {
        flb_plg_trace(conn->ctx->ins, "clear null byte at position %d",
                      nullbyte-(conn->buf_data) );
        *nullbyte = ' ';
    }

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

    process_pack(conn, pack, out_size);
    flb_free(pack);

    return conn->pack_state.last_byte;
}



/* Callback invoked every time an event is triggered for a connection */
int gelf_conn_event(void *data)
{
    int bytes;
    int available;
    int size;
    ssize_t ret_payload = -1;
    char *tmp;
    struct mk_event *event;
    struct gelf_conn *conn = data;
    struct flb_in_gelf_config *ctx = conn->ctx;

    event = &conn->event;
    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->chunk_size > ctx->buffer_size) {
                flb_plg_trace(ctx->ins,
                              "fd=%i incoming data exceed limit (%i KB)",
                              event->fd, (ctx->buffer_size / 1024));
                gelf_conn_del(conn);
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
            gelf_conn_del(conn);
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

        ret_payload = parse_json_payload(conn);
        if (ret_payload == 0) {
            /* nothing processed yet (incomplete JSON message), waiting for more data */
            return -1;
        }
        else if (ret_payload == -1) {
            flb_pack_state_reset(&conn->pack_state);
            flb_pack_state_init(&conn->pack_state);
            conn->pack_state.multiple = FLB_TRUE;
            return -1;
        }

        consume_bytes(conn->buf_data, ret_payload, conn->buf_len);
        conn->buf_len -= ret_payload;
        conn->buf_data[conn->buf_len] = '\0';

        jsmn_init(&conn->pack_state.parser);
        conn->pack_state.tokens_count = 0;
        conn->pack_state.last_byte = 0;
        conn->pack_state.buf_len = 0;

        return bytes;
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        gelf_conn_del(conn);
        return -1;
    }

    return 0;
}

/* Create a gelf request instance */
struct gelf_conn *gelf_conn_add(int fd, struct flb_in_gelf_config *ctx)
{
    int ret;
    struct gelf_conn *conn;
    struct mk_event *event;

    conn = flb_malloc(sizeof(struct gelf_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    /* Set data for the event-loop */
    event = &conn->event;
    MK_EVENT_NEW(event);
    event->fd           = fd;
    event->type         = FLB_ENGINE_EV_CUSTOM;
    event->handler      = gelf_conn_event;

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
    flb_pack_state_init(&conn->pack_state);
    conn->pack_state.multiple = FLB_TRUE;

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

int gelf_conn_del(struct gelf_conn *conn)
{
    struct flb_in_gelf_config *ctx;

    ctx = conn->ctx;

    flb_pack_state_reset(&conn->pack_state);
    /* Unregister the file descriptior from the event-loop */
    mk_event_del(ctx->evl, &conn->event);

    /* Release resources */
    mk_list_del(&conn->_head);
    flb_socket_close(conn->fd);
    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}

