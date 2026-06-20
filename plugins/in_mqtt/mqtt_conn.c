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

/* Callback invoked every time an event is triggered for a connection */
int mqtt_conn_event(void *data)
{
    int ret;
    int bytes;
    int available;
    struct mk_event *event;
    struct mqtt_conn *conn;
    struct flb_in_mqtt_config *ctx;
    struct flb_connection *connection;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    event = &connection->event;

    if (event->mask & MK_EVENT_READ) {
        available = conn->buf_size - conn->buf_len;

        bytes = flb_io_net_read(connection,
                                (void *) &conn->buf[conn->buf_len],
                                available);

        if (bytes > 0) {
            conn->buf_len += bytes;
            flb_plg_trace(ctx->ins, "[fd=%i] read()=%i bytes",
                          connection->fd,
                          bytes);

            ret = mqtt_prot_parser(conn);
            if (ret < 0) {
                mqtt_conn_del(conn);
                return -1;
            }
        }
        else {
            flb_plg_debug(ctx->ins, "[fd=%i] connection closed",
                          connection->fd);

            mqtt_conn_del(conn);
        }
    }
    else if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_debug(ctx->ins, "[fd=%i] hangup", event->fd);
    }

    return 0;
}

/* Create a new mqtt request instance */
struct mqtt_conn *mqtt_conn_add(struct flb_connection *connection,
                                struct flb_in_mqtt_config *ctx)
{
    struct mqtt_conn *conn;
    int               ret;

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

    /* Set data for the event-loop */
    MK_EVENT_NEW(&connection->event);

    connection->user_data     = conn;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = mqtt_conn_event;

    /* Connection info */
    conn->ctx     = ctx;
    conn->buf_pos = 0;
    conn->buf_len = 0;
    conn->buf_frame_end = 0;
    conn->status  = MQTT_NEW;

    /* Register instance into the event loop */
    ret = mk_event_add(flb_engine_evl_get(),
                       connection->fd,
                       FLB_ENGINE_EV_CUSTOM,
                       MK_EVENT_READ,
                       &connection->event);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");
        flb_free(conn);

        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->conns);

    return conn;
}

int mqtt_conn_del(struct mqtt_conn *conn)
{
    /* The downstream unregisters the file descriptor from the event-loop
     * so there's nothing to be done by the plugin
     */
    flb_downstream_conn_release(conn->connection);

    /* Release resources */
    mk_list_del(&conn->_head);

    if (conn->buf != NULL) {
        flb_free(conn->buf);
    }

    flb_free(conn);

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
