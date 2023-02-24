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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_downstream.h>

#include "fw.h"
#include "fw_prot.h"
#include "fw_conn.h"

/* Callback invoked every time an event is triggered for a connection */
int fw_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    int size;
    char *tmp;
    struct fw_conn *conn;
    struct mk_event *event;
    struct flb_in_fw_config *ctx;
    struct flb_connection *connection;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    event = &connection->event;


    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len);
        if (available < 1) {
            if (conn->buf_size >= ctx->buffer_max_size) {
                flb_plg_warn(ctx->ins, "fd=%i incoming data exceed limit (%lu bytes)",
                             event->fd, (ctx->buffer_max_size));
                fw_conn_del(conn);
                return -1;
            }
            else if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
                /* no space to add buffer_chunk_size */
                /* set maximum size */
                size = ctx->buffer_max_size;
            }
            else {
                size = conn->buf_size + ctx->buffer_chunk_size;
            }
            tmp = flb_realloc(conn->buf, size);
            if (!tmp) {
                flb_errno();
                return -1;
            }
            flb_plg_trace(ctx->ins, "fd=%i buffer realloc %i -> %i",
                          event->fd, conn->buf_size, size);

            conn->buf = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len);
        }

        bytes = flb_io_net_read(connection,
                                (void *) &conn->buf[conn->buf_len],
                                available);

        if (bytes > 0) {
            flb_plg_trace(ctx->ins, "read()=%i pre_len=%i now_len=%i",
                          bytes, conn->buf_len, conn->buf_len + bytes);
            conn->buf_len += bytes;

            ret = fw_prot_process(ctx->ins, conn);
            if (ret == -1) {
                fw_conn_del(conn);
                return -1;
            }
            return bytes;
        }
        else {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            fw_conn_del(conn);
            return -1;
        }
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        fw_conn_del(conn);
        return -1;
    }
    return 0;
}

/* Create a new Forward request instance */
struct fw_conn *fw_conn_add(struct flb_connection *connection, struct flb_in_fw_config *ctx)
{
    struct fw_conn *conn;
    int             ret;

    conn = flb_malloc(sizeof(struct fw_conn));
    if (!conn) {
        flb_errno();

        return NULL;
    }

    conn->connection = connection;

    /* Set data for the event-loop */
    connection->user_data     = conn;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = fw_conn_event;

    /* Connection info */
    conn->ctx     = ctx;
    conn->buf_len = 0;
    conn->rest    = 0;
    conn->status  = FW_NEW;

    /* Allocate read buffer */
    conn->buf = flb_malloc(ctx->buffer_chunk_size);
    if (!conn->buf) {
        flb_errno();
        flb_free(conn);

        return NULL;
    }
    conn->buf_size = ctx->buffer_chunk_size;
    conn->in       = ctx->ins;

    /* Register instance into the event loop */
    ret = mk_event_add(flb_engine_evl_get(),
                       connection->fd,
                       FLB_ENGINE_EV_CUSTOM,
                       MK_EVENT_READ,
                       &connection->event);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");

        flb_free(conn->buf);
        flb_free(conn);

        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->connections);

    return conn;
}

int fw_conn_del(struct fw_conn *conn)
{
    /* The downstream unregisters the file descriptor from the event-loop
     * so there's nothing to be done by the plugin
     */
    flb_downstream_conn_release(conn->connection);

    /* Release resources */
    mk_list_del(&conn->_head);

    flb_free(conn->buf);
    flb_free(conn);

    return 0;
}

int fw_conn_del_all(struct flb_in_fw_config *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct fw_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct fw_conn, _head);
        fw_conn_del(conn);
    }

    return 0;
}