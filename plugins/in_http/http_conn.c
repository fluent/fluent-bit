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
#include <fluent-bit/flb_engine.h>

#include "http.h"
#include "http_conn.h"
#include "http_prot.h"

static int http_conn_event(void *data)
{
    int ret;
    int status;
    size_t size;
    ssize_t available;
    ssize_t bytes;
    char *tmp;
    struct http_conn *conn = data;
    struct mk_event *event;
    struct flb_http *ctx = conn->ctx;
    struct mk_http_session *session;
    struct mk_http_request *request;

    event = &conn->event;
    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
                flb_plg_trace(ctx->ins,
                              "fd=%i incoming data exceed limit (%zu KB)",
                              event->fd, (ctx->buffer_max_size / 1024));
                http_conn_del(conn);
                return -1;
            }

            size = conn->buf_size + ctx->buffer_chunk_size;
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
            http_conn_del(conn);
            return -1;
        }

        flb_plg_trace(ctx->ins, "read()=%i pre_len=%i now_len=%i",
                      bytes, conn->buf_len, conn->buf_len + bytes);
        conn->buf_len += bytes;
        conn->buf_data[conn->buf_len] = '\0';

        session = &conn->session;
        request = mk_list_entry_first(&session->request_list,
                                 struct mk_http_request, _head);

        status = mk_http_parser(request, &session->parser,
                                conn->buf_data, conn->buf_len, NULL);
        if (status == MK_HTTP_PARSER_OK) {
            /* Do more logic parsing and checks for this request */
            ret = http_prot_handle(ctx, conn, session, request);
        }

        /* FIXME: add Protocol handler here */
        return bytes;
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        http_conn_del(conn);
        return -1;
    }

    return 0;

}

static void http_conn_session_init(struct mk_http_session *session,
                                   struct mk_server *server)
{
    /* Alloc memory for node */
    session->_sched_init = MK_TRUE;
    session->pipelined   = MK_FALSE;
    session->counter_connections = 0;
    session->close_now = MK_FALSE;
    session->socket = -1;
    session->status = MK_REQUEST_STATUS_INCOMPLETE;
    session->server = server;

    /* creation time in unix time */
    session->init_time = time(NULL);

    /* Init session request list */
    mk_list_init(&session->request_list);

    /* Initialize the parser */
    mk_http_parser_init(&session->parser);
}

struct http_conn *http_conn_add(int fd, struct flb_http *ctx)
{
    int ret;
    struct http_conn *conn;
    struct mk_event *event;

    conn = flb_calloc(1, sizeof(struct http_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    /* Set data for the event-loop */
    event = &conn->event;
    MK_EVENT_NEW(event);
    event->fd      = fd;
    event->type    = FLB_ENGINE_EV_CUSTOM;
    event->handler = http_conn_event;

    /* Connection info */
    conn->fd      = fd;
    conn->ctx     = ctx;
    conn->buf_len = 0;

    conn->buf_data = flb_malloc(ctx->buffer_chunk_size);
    if (!conn->buf_data) {
        flb_errno();
        flb_socket_close(fd);
        flb_plg_error(ctx->ins, "could not allocate new connection");
        flb_free(conn);
        return NULL;
    }
    conn->buf_size = ctx->buffer_chunk_size;

    /* Register instance into the event loop */
    ret = mk_event_add(ctx->evl, fd, FLB_ENGINE_EV_CUSTOM, MK_EVENT_READ, conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");
        flb_socket_close(fd);
        flb_free(conn->buf_data);
        flb_free(conn);
        return NULL;
    }

    /* Initialize HTTP Session: this is a custom context for Monkey HTTP */
    http_conn_session_init(&conn->session, ctx->server);

    /* Link connection node to parent context list */
    mk_list_add(&conn->_head, &ctx->connections);
    return conn;
}

int http_conn_del(struct http_conn *conn)
{
    struct flb_http *ctx;

    ctx = conn->ctx;

    mk_event_del(ctx->evl, &conn->event);
    mk_list_del(&conn->_head);
    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}

void http_conn_release_all(struct flb_http *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct http_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct http_conn, _head);
        http_conn_del(conn);
    }
}
