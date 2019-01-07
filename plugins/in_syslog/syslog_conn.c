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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>

#include "syslog.h"
#include "syslog_conf.h"
#include "syslog_conn.h"
#include "syslog_prot.h"

/* Callback invoked every time an event is triggered for a connection */
int syslog_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    int size;
    char *tmp;
    struct mk_event *event;
    struct syslog_conn *conn = data;
    struct flb_syslog *ctx = conn->ctx;

    event = &conn->event;
    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
                flb_debug("[in_syslog] fd=%i incoming data exceed limit (%i bytes)",
                          event->fd, (ctx->buffer_max_size));
                syslog_conn_del(conn);
                return -1;
            }

            size = conn->buf_size + ctx->buffer_chunk_size;
            tmp = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                flb_errno();
                return -1;
            }
            flb_trace("[in_syslog] fd=%i buffer realloc %i -> %i",
                      event->fd, conn->buf_size, size);

            conn->buf_data = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len) - 1;
        }

        bytes = read(conn->fd,
                     conn->buf_data + conn->buf_len, available);
        if (bytes > 0) {
            flb_trace("[in_syslog] read()=%i pre_len=%i now_len=%i",
                      bytes, conn->buf_len, conn->buf_len + bytes);
            conn->buf_len += bytes;
            conn->buf_data[conn->buf_len] = '\0';
            ret = syslog_prot_process(conn);
            if (ret == -1) {
                return -1;
            }
            return bytes;
        }
        else {
            flb_trace("[in_syslog] fd=%i closed connection", event->fd);
            syslog_conn_del(conn);
            return -1;
        }
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_trace("[in_syslog] fd=%i hangup", event->fd);
        syslog_conn_del(conn);
        return -1;
    }
    return 0;
}

/* Create a new mqtt request instance */
struct syslog_conn *syslog_conn_add(int fd, struct flb_syslog *ctx)
{
    int ret;
    struct syslog_conn *conn;
    struct mk_event *event;

    conn = flb_malloc(sizeof(struct syslog_conn));
    if (!conn) {
        return NULL;
    }

    /* Set data for the event-loop */
    event = &conn->event;
    MK_EVENT_NEW(event);
    event->fd           = fd;
    event->type         = FLB_ENGINE_EV_CUSTOM;
    event->handler      = syslog_conn_event;

    /* Connection info */
    conn->fd      = fd;
    conn->ctx     = ctx;
    conn->buf_len = 0;
    conn->buf_parsed = 0;
    conn->in      = ctx->i_ins;

    /* Allocate read buffer */
    conn->buf_data = flb_malloc(ctx->buffer_chunk_size);
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
        flb_error("[in_fw] could not register new connection");
        close(fd);
        flb_free(conn->buf_data);
        flb_free(conn);
        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->connections);

    return conn;
}

int syslog_conn_del(struct syslog_conn *conn)
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

int syslog_conn_exit(struct flb_syslog *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct syslog_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct syslog_conn, _head);
        syslog_conn_del(conn);
    }

    return 0;
}
