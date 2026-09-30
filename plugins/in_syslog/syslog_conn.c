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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_downstream.h>

#include "syslog.h"
#include "syslog_conf.h"
#include "syslog_conn.h"
#include "syslog_prot.h"

static void syslog_conn_drop(struct flb_connection *connection);

/* Callback invoked every time an event is triggered for a connection */
int syslog_conn_event(void *data)
{
    struct flb_connection *connection;
    struct syslog_conn    *conn;
    struct flb_syslog     *ctx;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    /* The wrapper might have been released by the drop notification */
    if (conn == NULL) {
        return -1;
    }

    ctx = conn->ctx;

    if (ctx->dgram_mode_flag) {
        return syslog_dgram_conn_event(data);
    }

    return syslog_stream_conn_event(data);
}

/* Parse and ingest buffered records outside of the connection coroutine */
static int syslog_stream_conn_process(void *data)
{
    return syslog_prot_process((struct syslog_conn *) data);
}

/*
 * Stream connections are served from a downstream event coroutine which
 * invokes this callback in a loop: the read below suspends the coroutine
 * until data is available, so every return path must either consume data
 * or release the connection.
 */
int syslog_stream_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    size_t size;
    char *tmp;
    struct syslog_conn *conn;
    struct flb_syslog *ctx;
    struct flb_connection *connection;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    available = (conn->buf_size - conn->buf_len) - 1;
    if (available < 1) {
        if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
            flb_plg_debug(ctx->ins,
                          "fd=%i incoming data exceed limit (%zd bytes)",
                          connection->fd, (ctx->buffer_max_size));
            syslog_conn_del(conn);
            return -1;
        }

        size = conn->buf_size + ctx->buffer_chunk_size;
        tmp = flb_realloc(conn->buf_data, size);
        if (!tmp) {
            flb_errno();
            syslog_conn_del(conn);
            return -1;
        }
        flb_plg_trace(ctx->ins, "fd=%i buffer realloc %zd -> %zd",
                      connection->fd, conn->buf_size, size);

        conn->buf_data = tmp;
        conn->buf_size = size;
        available = (conn->buf_size - conn->buf_len) - 1;
    }

    bytes = flb_io_net_read(connection,
                            (void *) &conn->buf_data[conn->buf_len],
                            available);

    if (bytes <= 0) {
        flb_plg_trace(ctx->ins, "fd=%i closed connection", connection->fd);
        syslog_conn_del(conn);
        return -1;
    }

    flb_plg_trace(ctx->ins, "read()=%i pre_len=%zu now_len=%zu",
                  bytes, conn->buf_len, conn->buf_len + bytes);
    conn->buf_len += bytes;
    conn->buf_data[conn->buf_len] = '\0';

    /*
     * Parsers, filters and processors run while records are appended, keep
     * them on the parent stack instead of the connection coroutine stack.
     */
    ret = flb_downstream_conn_event_call_parent(connection,
                                                syslog_stream_conn_process,
                                                conn);
    if (ret == -1) {
        syslog_conn_del(conn);
        return -1;
    }

    return bytes;
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
    struct syslog_conn *conn;

    conn = flb_malloc(sizeof(struct syslog_conn));
    if (!conn) {
        return NULL;
    }

    conn->connection = connection;

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

    connection->user_data = conn;

    mk_list_add(&conn->_head, &ctx->connections);

    /*
     * Stream connections are registered into the event loop by the
     * downstream accept coroutine and their wrapper is released from the
     * drop notification once the engine tears the connection down (UDP
     * events are received through the collector).
     */
    if (!ctx->dgram_mode_flag) {
        connection->drop_notification_callback = syslog_conn_drop;
    }

    return conn;
}

/* Release the plugin-side wrapper, the downstream connection is not touched */
static void syslog_conn_release(struct syslog_conn *conn)
{
    mk_list_del(&conn->_head);

    flb_free(conn->buf_data);
    flb_free(conn);
}

/*
 * Invoked by the engine (via prepare_destroy_conn) when the underlying
 * connection is destroyed, either on our request through syslog_conn_del
 * or on its own (e.g. an IO timeout).
 */
static void syslog_conn_drop(struct flb_connection *connection)
{
    struct syslog_conn *conn;

    conn = connection->user_data;

    connection->drop_notification_callback = NULL;
    connection->user_data = NULL;

    if (conn != NULL) {
        flb_plg_trace(conn->ctx->ins, "drop connection fd=%i", connection->fd);
        conn->connection = NULL;
        syslog_conn_release(conn);
    }
}

int syslog_conn_del(struct syslog_conn *conn)
{
    /*
     * The downstream unregisters the file descriptor from the event-loop
     * and may have to wake a callback suspended in asynchronous I/O before
     * releasing it, so the wrapper is freed by the drop notification in
     * both the immediate and the deferred paths.
     */
    if (!conn->ctx->dgram_mode_flag) {
        flb_downstream_conn_release(conn->connection);

        return 0;
    }

    syslog_conn_release(conn);

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
