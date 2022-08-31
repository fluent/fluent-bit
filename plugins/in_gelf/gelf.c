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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_pack.h>

#include "gelf.h"

static struct gelf_chunk_entry *gelf_chunk_tbl_add(struct gelf_chunk_tbl *tbl,
                                                   uint64_t msg_id,
                                                   struct gelf_chunk *chunk);

static int gelf_udp_message(struct flb_gelf *ctx, char *buffer_data,
                            size_t buffer_len, bool chunked);

static int gelf_chunk_tbl_resize(struct gelf_chunk_tbl *tbl, size_t new_size)
{
    int i;
    struct gelf_chunk_entry *new_entries;
    struct gelf_chunk_tbl new_tbl;

    if (new_size <= tbl->used) {
       return -1;
    }

    new_entries = flb_calloc(1, sizeof(struct gelf_chunk_entry) * new_size);
    if (!new_entries) {
       flb_errno();
       return -1;
    }

    new_tbl.size = new_size;
    new_tbl.used = 0;
    new_tbl.entries = new_entries;

    for (i=0; i < tbl->size; i++) {
        if (tbl->entries[i].msg_id != 0) {
            gelf_chunk_tbl_add(&new_tbl,
                               tbl->entries[i].msg_id,
                               tbl->entries[i].chunk);
        }
    }
    flb_free(tbl->entries);

    tbl->size = new_tbl.size;
    tbl->used = new_tbl.used;
    tbl->entries = new_entries;

    return 0;
}

static struct gelf_chunk_entry *gelf_chunk_tbl_add(struct gelf_chunk_tbl *tbl,
                                                   uint64_t msg_id,
                                                   struct gelf_chunk *chunk)
{
    uint64_t dib, pos;

    pos = msg_id % tbl->size;
    dib = 0;
    while(1) {
        if (tbl->entries[pos].msg_id == 0) {
            tbl->entries[pos].dib = dib;
            tbl->entries[pos].msg_id = msg_id;
            tbl->entries[pos].chunk = chunk;
            tbl->used++;
            return &(tbl->entries[pos]);
        }
        if (tbl->entries[pos].msg_id == msg_id) {
            return &(tbl->entries[pos]);
        }
        if (tbl->entries[pos].dib < dib) {
            uint64_t mv_msg_id = tbl->entries[pos].msg_id;
            struct gelf_chunk *mv_chunk = tbl->entries[pos].chunk;

            tbl->entries[pos].dib = dib;
            tbl->entries[pos].msg_id = msg_id;
            tbl->entries[pos].chunk = chunk;

            gelf_chunk_tbl_add(tbl, mv_msg_id, mv_chunk);
            return &(tbl->entries[pos]);
        }
        dib++;
        pos = (pos + 1) % tbl->size;
    }

    return NULL;
}

static struct gelf_chunk_entry *gelf_chunk_tbl_get(struct gelf_chunk_tbl *tbl,
                                                   uint64_t msg_id,
                                                   uint8_t seq_cnt)
{
    struct gelf_chunk_entry *entry;
    struct gelf_chunk *chunk;

    if ((tbl->used * 3) > (tbl->size * 2)) {
        if (gelf_chunk_tbl_resize(tbl, tbl->size * 2) < 0) {
            return NULL;
        }
    }

    entry = gelf_chunk_tbl_add(tbl, msg_id, NULL);
    if (!entry) {
        return NULL;
    }

    if (!entry->chunk) {
        entry->msg_id = msg_id;
        chunk = flb_calloc(1, sizeof(struct gelf_chunk) +
                              sizeof(struct gelf_chunk_sgmt)*seq_cnt);
        if (!chunk) {
            flb_errno();
            return NULL;
        }
        chunk->start = time(NULL);
        chunk->sgmt_cnt = seq_cnt;
        entry->chunk = chunk;

        return entry;
    }

    return entry;
}

static void gelf_chunk_tbl_entry_free(struct gelf_chunk_tbl *tbl,
                                      struct gelf_chunk_entry *entry)
{
    int i;

    if (!entry) {
       return;
    }

    if (entry->chunk) {
        for (i = 0; i < entry->chunk->sgmt_cnt; i++) {
            if (entry->chunk->sgmt[i].base) {
                flb_free(entry->chunk->sgmt[i].base);
            }
        }
        flb_free(entry->chunk);
        entry->chunk = NULL;
    }

    entry->dib = 0;
    entry->msg_id = 0;
    tbl->used--;
}

static int gelf_chunk_tbl_alloc(struct gelf_chunk_tbl *tbl)
{
    if (tbl->entries == NULL) {
        tbl->size = FLB_GELF_TBL_SIZE;
        tbl->used = 0;
        tbl->entries = flb_calloc(1,
                                  sizeof(struct gelf_chunk_entry) * tbl->size);
        if (!tbl->entries) {
            flb_errno();
            return -1;
        }
    }
    return 0;
}

static void gelf_chunk_tbl_free(struct gelf_chunk_tbl *tbl)
{
    int i;

    if (!tbl->entries) {
       return;
    }

    for (i=0; i < tbl->size; i++) {
        if (tbl->entries[i].msg_id) {
            gelf_chunk_tbl_entry_free(tbl, &tbl->entries[i]);
        }
    }

    flb_free(tbl->entries);
    tbl->entries = NULL;
    tbl->used = 0;
}

static int in_gelf_purge_udp(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct flb_gelf *ctx = in_context;
    struct gelf_chunk_tbl *tbl;
    int i;
    time_t now;
    (void) ins;

    tbl = &ctx->chunks;
    if (!tbl->entries) {
        return 0;
    }

    now = time(NULL);
    for (i=0; i < tbl->size; i++) {
        if (!tbl->entries[i].msg_id) {
            continue;
        }
        if (tbl->entries[i].chunk) {
            if ((now - tbl->entries[i].chunk->start) > FLB_GELF_CHUNK_TMOUT) {
                gelf_chunk_tbl_entry_free(tbl, &tbl->entries[i]);
            }
        }
        else {
            gelf_chunk_tbl_entry_free(tbl, &tbl->entries[i]);
        }
    }

    if (tbl->size <= FLB_GELF_TBL_SIZE) {
        return 0;
    }

    if ((tbl->used * 5) < tbl->size) {
        tbl->resize_hits++;
        if (tbl->resize_hits < 60) {
            return 0;
        }
        int new_size = tbl->used * 3;
        if (new_size < FLB_GELF_TBL_SIZE) {
            new_size = FLB_GELF_TBL_SIZE;
        }
        gelf_chunk_tbl_resize(tbl, new_size);
    } else {
        tbl->resize_hits = 0;
    }

    return 0;
}

static int gelf_chunk_append (struct flb_gelf *ctx,
                              uint8_t *buffer, size_t buffer_size)
{
    int i;
    size_t len;
    uint64_t msg_id;
    uint8_t seq_num;
    uint8_t seq_cnt;
    size_t data_size;
    void *data;
    char *msg;
    struct gelf_chunk_entry *entry;
    struct gelf_chunk *chunk;

    if (buffer_size <= FLB_GELF_HEADER_SIZE) {
        flb_plg_error(ctx->ins, "chunked message is too short");
        return -1;
    }

    seq_num = *(buffer + FLB_GELF_HEADER_SEQNUM);
    seq_cnt = *(buffer + FLB_GELF_HEADER_SEQCNT);
    msg_id = *(uint64_t *)(buffer + FLB_GELF_HEADER_ID);

    if (msg_id == 0) {
        flb_plg_error(ctx->ins, "chunked message with zero message id");
        return -1;
    }

    if ((seq_num > 127) || (seq_cnt > 128)) {
        flb_plg_error(ctx->ins, "chunked message with more than 128 segments");
        return -1;
    }

    if (seq_num >= seq_cnt) {
        flb_plg_error(ctx->ins, "chunked message with sequence number "
                  "greater than total segments");
        return -1;
    }

    data = buffer + FLB_GELF_HEADER_SIZE;
    data_size = buffer_size - FLB_GELF_HEADER_SIZE;

    entry = gelf_chunk_tbl_get(&ctx->chunks, msg_id, seq_cnt);
    if (entry == NULL) {
        flb_plg_error(ctx->ins, "cannot get a slot for the chunked message");
        return -1;
    }
    chunk = entry->chunk;

    if (chunk->sgmt_cnt != seq_cnt) {
        flb_plg_error(ctx->ins, "chunked message with "
                                "different number of segments");
        gelf_chunk_tbl_entry_free(&ctx->chunks, entry);
        return -1;
    }

    if (chunk->sgmt[seq_num].base) {
        flb_plg_error(ctx->ins, "chunked message already recived");
        gelf_chunk_tbl_entry_free(&ctx->chunks, entry);
        return -1;
    }

    chunk->sgmt[seq_num].base = flb_malloc(data_size);
    if (!chunk->sgmt[seq_num].base) {
        flb_errno();
        gelf_chunk_tbl_entry_free(&ctx->chunks, entry);
        return -1;
    }
    chunk->sgmt[seq_num].len = data_size;
    memcpy(chunk->sgmt[seq_num].base, data, data_size);

    chunk->sgmt_found++;

    if (chunk->sgmt_found != chunk->sgmt_cnt) {
        /* we need more segments */
        return 0;
    }

    len = 0;
    for (i = 0; i < seq_cnt; i++) {
        if (chunk->sgmt[i].len == 0) {
             break;
        }
        len += chunk->sgmt[i].len;
    }

    if (i != seq_cnt) {
        flb_plg_error(ctx->ins, "chunked message with missing segments");
        gelf_chunk_tbl_entry_free(&ctx->chunks, entry);
        return -1;
    }

    if (len == 0) {
        flb_plg_error(ctx->ins, "chunked message with 0 total bytes");
        gelf_chunk_tbl_entry_free(&ctx->chunks, entry);
        return -1;
    }

    msg = flb_malloc(len);
    if (!msg) {
        flb_errno();
        gelf_chunk_tbl_entry_free(&ctx->chunks, entry);
        return -1;
    }

    len = 0;
    for (i = 0; i < seq_cnt; i++) {
        memcpy(msg + len, chunk->sgmt[i].base, chunk->sgmt[i].len);
        len += chunk->sgmt[i].len;
    }
    gelf_chunk_tbl_entry_free(&ctx->chunks, entry);

    gelf_udp_message(ctx, msg, len, true);

    flb_free(msg);
    return 0;
}

static int gelf_pack_message(struct flb_gelf *ctx,
                             char *data, size_t data_size)
{
    int ret;
    struct flb_time tm;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    char *packed_data = NULL;
    size_t packed_size = 0;

    flb_time_zero(&tm);
    ret = flb_gelf_to_msgpack(data, data_size, &tm,
                              &packed_data, &packed_size, ctx->strict);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "failed to convert gelf message to msgpack");
        return -1;
    }

    if ((tm.tm.tv_sec == 0) && (tm.tm.tv_nsec == 0)) {
        flb_time_get(&tm);
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(&tm, &mp_pck, 0);
    msgpack_sbuffer_write(&mp_sbuf, packed_data, packed_size);

    flb_input_chunk_append_raw(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_free(packed_data);
    return 0;
}

static int gelf_message_type(uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < 2) {
        return FLB_GELF_TYPE_UNSUPPORTED;
    }

    if (buffer[0] == 0x78) {
        uint16_t flg, cmf;
        cmf = buffer[0];
        flg = buffer[1];
        if ((256 * cmf + flg) % 31 == 0) {
            return FLB_GELF_TYPE_ZLIB;
        }
        else {
            return FLB_GELF_TYPE_UNSUPPORTED;
        }
    }
    else if (buffer[0] == 0x1f) {
        if (buffer[1] == 0x8b) {
            return FLB_GELF_TYPE_GZIP;
        }
        else {
            return FLB_GELF_TYPE_UNSUPPORTED;
        }
    }
    else if (buffer[0] == 0x1e) {
        if (buffer[1] == 0x0f) {
            return FLB_GELF_TYPE_CHUNKED;
        }
        else {
            return FLB_GELF_TYPE_UNSUPPORTED;
        }
    }

    return FLB_GELF_TYPE_UNCOMPRESSED;
}

static int gelf_udp_message(struct flb_gelf *ctx, char *buffer_data,
                            size_t buffer_len, bool chunked)
{
    int ret = -1;
    int type;
    void *out_msg = NULL;
    size_t out_msg_size = 0;

    type = gelf_message_type((uint8_t *)buffer_data, buffer_len);

    if (type == FLB_GELF_TYPE_GZIP) {
        ret = flb_gzip_uncompress((void *)buffer_data, buffer_len,
                                  &out_msg, &out_msg_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "failed to uncompress gzip message");
            return -1;
        }
        if (out_msg != NULL) {
            gelf_pack_message(ctx, out_msg, out_msg_size);
            flb_free(out_msg);
        }
    }
    else if (type == FLB_GELF_TYPE_CHUNKED) {
        if (chunked) {
            flb_plg_error(ctx->ins, "nested chunked message");
            return -1;
        }
        gelf_chunk_append (ctx, (uint8_t *)buffer_data, buffer_len);
    }
    else if (type == FLB_GELF_TYPE_ZLIB) {
        ret = flb_zlib_uncompress((void *)buffer_data, buffer_len,
                                  &out_msg, &out_msg_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "failed to uncompress lzib message");
            return -1;
        }
        if (out_msg != NULL) {
            gelf_pack_message(ctx, out_msg, out_msg_size);
            flb_free(out_msg);
        }
    }
    else if (type == FLB_GELF_TYPE_UNCOMPRESSED) {
        gelf_pack_message(ctx, buffer_data, buffer_len);
    }
    else {
        flb_plg_error(ctx->ins, "unsupported message type");
        return -1;
    }

    return 0;
}

static int gelf_tcp_message(struct gelf_tcp_conn *conn)
{
    size_t len;
    char *zero;
    struct flb_gelf *ctx = conn->ctx;

    while (1) {
        zero = memchr(conn->buf_data, 0, conn->buf_len);
        if (!zero) {
           break;
        }
        len = zero - conn->buf_data + 1;

        gelf_pack_message(ctx, conn->buf_data, len -1);

        memmove(conn->buf_data, conn->buf_data + len, conn->buf_len - len);
        conn->buf_len -= len;
        if (!conn->buf_len) {
            break;
        }
    }
    return 0;
}

static int gelf_tcp_conn_del(struct gelf_tcp_conn *conn)
{
    /* Unregister the file descriptior from the event-loop */
    mk_event_del(conn->ctx->evl, &conn->event);

    /* Release resources */
    mk_list_del(&conn->_head);
    close(conn->fd);
    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}

static int gelf_tcp_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    size_t size;
    char *tmp;
    struct mk_event *event;
    struct gelf_tcp_conn *conn = data;
    struct flb_gelf *ctx = conn->ctx;

    event = &conn->event;
    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->buffer_chunk_size >
                ctx->buffer_max_size) {
                flb_plg_debug(ctx->ins,
                              "fd=%i incoming data exceed limit (%zd bytes)",
                              event->fd, (ctx->buffer_max_size));
                gelf_tcp_conn_del(conn);
                return -1;
            }

            size = conn->buf_size + ctx->buffer_chunk_size;
            tmp = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                gelf_tcp_conn_del(conn);
                flb_errno();
                return -1;
            }
            flb_plg_trace(ctx->ins, "fd=%i buffer realloc %zd -> %zd",
                          event->fd, conn->buf_size, size);

            conn->buf_data = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len) - 1;
        }

        bytes = read(conn->fd, conn->buf_data + conn->buf_len, available);
        if (bytes > 0) {
            flb_plg_trace(ctx->ins, "read()=%i pre_len=%zu now_len=%zu",
                          bytes, conn->buf_len, conn->buf_len + bytes);
            conn->buf_len += bytes;
            ret = gelf_tcp_message(conn);
            if (ret == -1) {
                return -1;
            }
            return bytes;
        }
        else {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            gelf_tcp_conn_del(conn);
            return -1;
        }
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        gelf_tcp_conn_del(conn);
        return -1;
    }
    return 0;
}

static struct gelf_tcp_conn *gelf_tcp_conn_add(int fd, struct flb_gelf *ctx)
{
    int ret;
    struct gelf_tcp_conn *conn;
    struct mk_event *event;

    conn = flb_calloc(1, sizeof(struct gelf_tcp_conn));
    if (!conn) {
        return NULL;
    }

    /* Set data for the event-loop */
    event = &conn->event;
    MK_EVENT_NEW(event);
    event->fd      = fd;
    event->type    = FLB_ENGINE_EV_CUSTOM;
    event->handler = gelf_tcp_conn_event;

    /* Connection info */
    conn->fd         = fd;
    conn->ctx        = ctx;
    conn->ins        = ctx->ins;
    conn->buf_len    = 0;
    conn->buf_parsed = 0;

    /* Allocate read buffer */
    conn->buf_data = flb_calloc(1, ctx->buffer_chunk_size);
    if (!conn->buf_data) {
        flb_errno();
        close(fd);
        flb_free(conn);
        return NULL;
    }
    conn->buf_size = ctx->buffer_chunk_size;

    /* Register instance into the event loop */
    ret = mk_event_add(ctx->evl, fd, FLB_ENGINE_EV_CUSTOM, MK_EVENT_READ, conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");
        close(fd);
        flb_free(conn->buf_data);
        flb_free(conn);
        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->connections);

    return conn;
}

static int gelf_tcp_conn_exit(struct flb_gelf *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct gelf_tcp_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct gelf_tcp_conn, _head);
        gelf_tcp_conn_del(conn);
    }

    return 0;
}

static int gelf_server_create(struct flb_gelf *ctx)
{
    if (ctx->mode == FLB_GELF_UDP) {
        ctx->buffer_data = flb_calloc(1, ctx->buffer_chunk_size);
        if (!ctx->buffer_data) {
            flb_errno();
            return -1;
        }
        ctx->buffer_size = ctx->buffer_chunk_size;
        flb_info("[in_gelf] UDP buffer size set to %lu bytes",
                 ctx->buffer_size);
    }

    if (ctx->mode == FLB_GELF_TCP) {
        ctx->server_fd = flb_net_server(ctx->port, ctx->listen);
    }
    else {
        ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen);
    }

    if (ctx->server_fd > 0) {
        flb_info("[in_gelf] %s server binding %s:%s",
                 ((ctx->mode == FLB_GELF_TCP) ? "TCP" : "UDP"),
                 ctx->listen, ctx->port);
    }
    else {
        flb_plg_error(ctx->ins, "could not bind address %s:%s. Aborting",
                  ctx->listen, ctx->port);
        return -1;
    }

    flb_net_socket_nonblocking(ctx->server_fd);

    return 0;
}

struct flb_gelf *gelf_conf_create(struct flb_input_instance *ins,
                                  struct flb_config *config)
{
    const char *tmp;
    struct flb_gelf *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_gelf));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->evl = config->evl;
    ctx->ins = ins;
    ctx->buffer_data = NULL;
    mk_list_init(&ctx->connections);

    tmp = flb_input_get_property("mode", ins);
    if (tmp) {
        if (strcasecmp(tmp, "tcp") == 0) {
            ctx->mode = FLB_GELF_TCP;
        }
        else if (strcasecmp(tmp, "udp") == 0) {
            ctx->mode = FLB_GELF_UDP;
        }
        else {
            flb_plg_error(ctx->ins, "Unknown gelf mode %s", tmp);
            flb_free(ctx);
            return NULL;
        }
    }
    else {
        ctx->mode = FLB_GELF_UDP;
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:12201) */
    flb_input_net_default_listener("0.0.0.0", 12201, ins);
    ctx->listen = ins->host.listen;
    snprintf(ctx->port, sizeof(ctx->port) - 1, "%d", ins->host.port);
    ctx->port[sizeof(ctx->port)-1] = '\0';

    /* Buffer Chunk Size */
    tmp = flb_input_get_property("buffer_chunk_size", ins);
    if (!tmp) {
        ctx->buffer_chunk_size = FLB_GELF_CHUNK;
    }
    else {
        ctx->buffer_chunk_size = flb_utils_size_to_bytes(tmp);
    }

    /* Buffer Max Size */
    tmp = flb_input_get_property("buffer_max_size", ins);
    if (!tmp) {
        ctx->buffer_max_size = ctx->buffer_chunk_size;
    }
    else {
        ctx->buffer_max_size  = flb_utils_size_to_bytes(tmp);
    }

    /* Strict parser */
    tmp = flb_input_get_property("strict_parser", ins);
    if (tmp) {
        ctx->strict = flb_utils_bool(tmp);
    }
    else {
        ctx->strict = FLB_TRUE;
    }

    return ctx;
}

int gelf_conf_destroy(struct flb_gelf *ctx)
{
    if (ctx->buffer_data) {
        flb_free(ctx->buffer_data);
        ctx->buffer_data = NULL;
    }

    close(ctx->server_fd);

    flb_free(ctx);

    return 0;
}

static int in_gelf_collect_tcp(struct flb_input_instance *i_ins,
                               struct flb_config *config,
                               void *in_context)
{
    int fd;
    struct flb_gelf *ctx = in_context;
    struct gelf_tcp_conn *conn;
    (void) i_ins;

    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_plg_error(ctx->ins, "could not accept new connection");
        return -1;
    }

    flb_plg_debug(ctx->ins, "new connection arrived FD=%i", fd);
    conn = gelf_tcp_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }

    return 0;
}

static int in_gelf_collect_udp(struct flb_input_instance *i_ins,
                               struct flb_config *config,
                               void *in_context)
{
    int bytes;
    struct flb_gelf *ctx = in_context;
    (void) i_ins;

    bytes = recvfrom(ctx->server_fd,
                     ctx->buffer_data, ctx->buffer_size, 0,
                     NULL, NULL);
    if (bytes > 0) {
        ctx->buffer_len = bytes;
        gelf_udp_message(ctx, ctx->buffer_data, ctx->buffer_len, false);
    }
    else {
        flb_errno();
    }
    ctx->buffer_len = 0;

    return 0;
}

static int in_gelf_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = 0;
    struct flb_gelf *ctx;

    ctx = gelf_conf_create(in, config);
    if (!ctx) {
        flb_plg_error(in, "could not initialize plugin");
        return -1;
    }

    ret = gelf_server_create(ctx);
    if (ret == -1) {
        gelf_conf_destroy(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);

    if (ctx->mode == FLB_GELF_TCP) {
        ret = flb_input_set_collector_socket(in,
                                             in_gelf_collect_tcp,
                                             ctx->server_fd,
                                             config);
    }
    else {
        ret = flb_input_set_collector_socket(in,
                                             in_gelf_collect_udp,
                                             ctx->server_fd,
                                             config);
        if (ret != -1) {
            ret = flb_input_set_collector_time(in,
                                               in_gelf_purge_udp,
                                               1, 0,
                                               config);
        }
        if (ret != -1) {
            ret = gelf_chunk_tbl_alloc(&ctx->chunks);
        }
    }

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector");
        gelf_conf_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_gelf_exit(void *data, struct flb_config *config)
{
    struct flb_gelf *ctx = data;
    (void) config;

    if (ctx->mode == FLB_GELF_TCP) {
        gelf_tcp_conn_exit(ctx);
    }
    else {
        gelf_chunk_tbl_free(&ctx->chunks);
    }

    gelf_conf_destroy(ctx);

    return 0;
}

struct flb_input_plugin in_gelf_plugin = {
    .name         = "gelf",
    .description  = "gelf",
    .cb_init      = in_gelf_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_gelf_exit,
    .flags        = FLB_INPUT_NET
};
