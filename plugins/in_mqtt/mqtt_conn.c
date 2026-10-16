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

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_downstream.h>

#include "mqtt.h"
#include "mqtt_prot.h"
#include "mqtt_conn.h"

static void mqtt_conn_drop(struct flb_connection *connection);

/*
 * Callback invoked from the downstream event coroutine of the connection. It
 * is called in a loop and the read below suspends the coroutine until data
 * is available, so every return path must either consume data or release
 * the connection.
 */
int mqtt_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    struct mqtt_conn *conn;
    struct flb_in_mqtt_config *ctx;
    struct flb_connection *connection;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    /* The wrapper might have been released by the drop notification */
    if (conn == NULL) {
        return -1;
    }

    ctx = conn->ctx;

    available = conn->buf_size - conn->buf_len;
    if (available < 1) {
        flb_plg_debug(ctx->ins, "[fd=%i] incoming packet exceeds buffer_size",
                      connection->fd);

        mqtt_conn_del(conn);

        return -1;
    }

    bytes = flb_io_net_read(connection,
                            (void *) &conn->buf[conn->buf_len],
                            available);

    if (bytes <= 0) {
        flb_plg_debug(ctx->ins, "[fd=%i] connection closed",
                      connection->fd);

        mqtt_conn_del(conn);

        return -1;
    }

    conn->buf_len += bytes;
    flb_plg_trace(ctx->ins, "[fd=%i] read()=%i bytes",
                  connection->fd,
                  bytes);

    ret = mqtt_prot_parser(conn);
    if (ret < 0) {
        mqtt_conn_del(conn);
        return -1;
    }

    return 0;
}

/* Create a new mqtt request instance */
struct mqtt_conn *mqtt_conn_add(struct flb_connection *connection,
                                struct flb_in_mqtt_config *ctx)
{
    struct mqtt_conn *conn;

    conn = flb_malloc(sizeof(struct mqtt_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    conn->buf = flb_calloc(ctx->buffer_size, 1);

    if (conn->buf == NULL) {
        flb_errno();
        flb_free(conn);
        return NULL;
    }

    conn->buf_size = ctx->buffer_size;

    conn->connection = connection;

    connection->user_data     = conn;

    /* Connection info */
    conn->ctx     = ctx;
    conn->buf_pos = 0;
    conn->buf_len = 0;
    conn->buf_frame_end = 0;
    conn->status  = MQTT_NEW;

    mk_list_add(&conn->_head, &ctx->conns);

    /*
     * The connection is registered into the event loop by the downstream
     * accept coroutine and the wrapper is released from the drop
     * notification once the engine tears the connection down.
     */
    connection->drop_notification_callback = mqtt_conn_drop;

    return conn;
}

/* Release the plugin-side wrapper, the downstream connection is not touched */
static void mqtt_conn_release(struct mqtt_conn *conn)
{
    mk_list_del(&conn->_head);

    if (conn->buf != NULL) {
        flb_free(conn->buf);
    }

    flb_free(conn);
}

/*
 * Invoked by the engine (via prepare_destroy_conn) when the underlying
 * connection is destroyed, either on our request through mqtt_conn_del
 * or on its own (e.g. an IO timeout).
 */
static void mqtt_conn_drop(struct flb_connection *connection)
{
    struct mqtt_conn *conn;

    conn = connection->user_data;

    connection->drop_notification_callback = NULL;
    connection->user_data = NULL;

    if (conn != NULL) {
        flb_plg_trace(conn->ctx->ins, "[fd=%i] drop connection",
                      connection->fd);
        conn->connection = NULL;
        mqtt_conn_release(conn);
    }
}

int mqtt_conn_del(struct mqtt_conn *conn)
{
    /*
     * The downstream unregisters the file descriptor from the event-loop
     * and may have to wake a callback suspended in asynchronous I/O before
     * releasing it, so the wrapper is freed by the drop notification in
     * both the immediate and the deferred paths.
     */
    flb_downstream_conn_release(conn->connection);

    return 0;
}

int mqtt_conn_destroy_all(struct flb_in_mqtt_config *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mqtt_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->conns) {
        conn = mk_list_entry(head, struct mqtt_conn, _head);
        mqtt_conn_del(conn);
    }

    return 0;
}
