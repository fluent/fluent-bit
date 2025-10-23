/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_downstream.h>

#include "syslog.h"
#include "syslog_conf.h"
#include "syslog_conn.h"
#include "syslog_prot.h"

/* Callback invoked every time an event is triggered for a connection */
int syslog_conn_event(void *data)
{
    struct flb_connection *connection;
    struct syslog_conn    *conn;
    struct flb_syslog     *ctx;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    if (ctx->dgram_mode_flag) {
        return syslog_dgram_conn_event(data);
    }

    return syslog_stream_conn_event(data);
}

int syslog_stream_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    size_t size;
    char *tmp;
    struct mk_event *event;
    struct syslog_conn *conn;
    struct flb_syslog *ctx;
    struct flb_connection *connection;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    event = &connection->event;

    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
                flb_plg_debug(ctx->ins,
                              "fd=%i incoming data exceed limit (%zd bytes)",
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
            flb_plg_trace(ctx->ins, "fd=%i buffer realloc %zd -> %zd",
                          event->fd, conn->buf_size, size);

            conn->buf_data = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len) - 1;
        }

        bytes = flb_io_net_read(connection,
                                (void *) &conn->buf_data[conn->buf_len],
                                available);

        if (bytes > 0) {
            flb_plg_trace(ctx->ins, "read()=%i pre_len=%zu now_len=%zu",
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
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            syslog_conn_del(conn);
            return -1;
        }
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        syslog_conn_del(conn);
        return -1;
    }
    return 0;
}

int syslog_dgram_conn_event(void *data)
{
    struct flb_connection *connection;
    int                    bytes;
    struct syslog_conn    *conn;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    bytes = flb_io_net_read(connection,
                            (void *) &conn->buf_data[conn->buf_len],
                            conn->buf_size - 1);

    if (bytes > 0) {
        conn->buf_data[bytes] = '\0';
        conn->buf_len = bytes;

        syslog_prot_process_udp(conn);
    }
    else {
        flb_errno();
    }

    conn->buf_len = 0;

    return 0;
}

/* Create a new mqtt request instance */
struct syslog_conn *syslog_conn_add(struct flb_connection *connection,
                                    struct flb_syslog *ctx)
{
    int ret;
    struct syslog_conn *conn;

    conn = flb_malloc(sizeof(struct syslog_conn));
    if (!conn) {
        return NULL;
    }

    conn->connection = connection;

    /* Set data for the event-loop */
    MK_EVENT_NEW(&connection->event);

    connection->user_data     = conn;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = syslog_conn_event;

    /* Connection info */
    conn->ctx     = ctx;
    conn->ins     = ctx->ins;
    conn->buf_len = 0;
    conn->buf_parsed = 0;
    conn->frame_expected_len = 0;
    conn->frame_have_len = 0;

    /* Allocate read buffer */
    conn->buf_data = flb_malloc(ctx->buffer_chunk_size);
    if (!conn->buf_data) {
        flb_errno();

        flb_free(conn);

        return NULL;
    }
    conn->buf_size = ctx->buffer_chunk_size;

    /* Register instance into the event loop if we're in
     * stream mode (UDP events are received through the collector)
     */
    if (!ctx->dgram_mode_flag) {
        ret = mk_event_add(flb_engine_evl_get(),
                           connection->fd,
                           FLB_ENGINE_EV_CUSTOM,
                           MK_EVENT_READ,
                           &connection->event);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not register new connection");

            flb_free(conn->buf_data);
            flb_free(conn);

            return NULL;
        }
    }

    mk_list_add(&conn->_head, &ctx->connections);

    return conn;
}

int syslog_conn_del(struct syslog_conn *conn)
{
    /* The downstream unregisters the file descriptor from the event-loop
     * so there's nothing to be done by the plugin
     */
    if (!conn->ctx->dgram_mode_flag) {
        flb_downstream_conn_release(conn->connection);
    }

    /* Release resources */
    mk_list_del(&conn->_head);

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
