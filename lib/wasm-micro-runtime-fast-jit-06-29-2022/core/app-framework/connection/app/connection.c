/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wa-inc/connection.h"
#include "connection_api.h"

/* Raw connection structure */
typedef struct _connection {
    /* Next connection */
    struct _connection *next;

    /* Handle of the connection */
    uint32 handle;

    /* Callback function called when event on this connection occurs */
    on_connection_event_f on_event;

    /* User data */
    void *user_data;
} connection_t;

/* Raw connections list */
static connection_t *g_conns = NULL;

connection_t *
api_open_connection(const char *name, attr_container_t *args,
                    on_connection_event_f on_event, void *user_data)
{
    connection_t *conn;
    char *args_buffer = (char *)args;
    uint32 handle, args_len = attr_container_get_serialize_length(args);

    handle = wasm_open_connection(name, args_buffer, args_len);
    if (handle == -1)
        return NULL;

    conn = (connection_t *)malloc(sizeof(*conn));
    if (conn == NULL) {
        wasm_close_connection(handle);
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));
    conn->handle = handle;
    conn->on_event = on_event;
    conn->user_data = user_data;

    if (g_conns != NULL) {
        conn->next = g_conns;
        g_conns = conn;
    }
    else {
        g_conns = conn;
    }

    return conn;
}

void
api_close_connection(connection_t *c)
{
    connection_t *conn = g_conns, *prev = NULL;

    while (conn) {
        if (conn == c) {
            wasm_close_connection(c->handle);
            if (prev != NULL)
                prev->next = conn->next;
            else
                g_conns = conn->next;
            free(conn);
            return;
        }
        else {
            prev = conn;
            conn = conn->next;
        }
    }
}

int
api_send_on_connection(connection_t *conn, const char *data, uint32 len)
{
    return wasm_send_on_connection(conn->handle, data, len);
}

bool
api_config_connection(connection_t *conn, attr_container_t *cfg)
{
    char *cfg_buffer = (char *)cfg;
    uint32 cfg_len = attr_container_get_serialize_length(cfg);

    return wasm_config_connection(conn->handle, cfg_buffer, cfg_len);
}

void
on_connection_data(uint32 handle, char *buffer, uint32 len)
{
    connection_t *conn = g_conns;

    while (conn != NULL) {
        if (conn->handle == handle) {
            if (len == 0) {
                conn->on_event(conn, CONN_EVENT_TYPE_DISCONNECT, NULL, 0,
                               conn->user_data);
            }
            else {
                conn->on_event(conn, CONN_EVENT_TYPE_DATA, buffer, len,
                               conn->user_data);
            }

            return;
        }
        conn = conn->next;
    }
}
