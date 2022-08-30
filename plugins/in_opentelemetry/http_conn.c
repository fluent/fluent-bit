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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_engine.h>

#include "opentelemetry.h"
#include "http_conn.h"
#include "opentelemetry_prot.h"

static void opentelemetry_conn_request_init(struct mk_http_session *session,
                                   struct mk_http_request *request);

static int opentelemetry_conn_event(void *data)
{
    int status;
    size_t size;
    ssize_t available;
    ssize_t bytes;
    char *tmp;
    char *request_end;
    size_t request_len;
    struct http_conn *conn = data;
    struct mk_event *event;
    struct flb_opentelemetry *ctx = conn->ctx;

    event = &conn->event;
    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
                flb_plg_trace(ctx->ins,
                              "fd=%i incoming data exceed limit (%zu KB)",
                              event->fd, (ctx->buffer_max_size / 1024));
                opentelemetry_conn_del(conn);
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
        bytes = recv(conn->fd, conn->buf_data + conn->buf_len, available, 0);
        if (bytes <= 0) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            opentelemetry_conn_del(conn);
            return -1;
        }

        flb_plg_trace(ctx->ins, "read()=%i pre_len=%i now_len=%i",
                      bytes, conn->buf_len, conn->buf_len + bytes);
        conn->buf_len += bytes;
        conn->buf_data[conn->buf_len] = '\0';

        status = mk_http_parser(&conn->request, &conn->session.parser,
                                conn->buf_data, conn->buf_len, conn->session.server);

        if (status == MK_HTTP_PARSER_OK) {
            /* Do more logic parsing and checks for this request */
            opentelemetry_prot_handle(ctx, conn, &conn->session, &conn->request);

            /* Evict the processed request from the connection buffer and reinitialize
             * the HTTP parser.
             */

            request_end = NULL;

            if (NULL != conn->request.data.data) {
                request_end = &conn->request.data.data[conn->request.data.len];
            }
            else {
                request_end = strstr(conn->buf_data, "\r\n\r\n");

                if(NULL != request_end) {
                    request_end = &request_end[4];
                }
            }

            if (NULL != request_end) {
                request_len = (size_t)(request_end - conn->buf_data);

                if (0 < (conn->buf_len - request_len)) {
                    memmove(conn->buf_data, &conn->buf_data[request_len],
                            conn->buf_len - request_len);

                    conn->buf_data[conn->buf_len - request_len] = '\0';
                    conn->buf_len -= request_len;
                }
                else {
                    memset(conn->buf_data, 0, request_len);

                    conn->buf_len = 0;
                }

                /* Reinitialize the parser so the next request is properly
                 * handled, the additional memset intends to wipe any left over data
                 * from the headers parsed in the previous request.
                 */
                memset(&conn->session.parser, 0, sizeof(struct mk_http_parser));
                mk_http_parser_init(&conn->session.parser);
                opentelemetry_conn_request_init(&conn->session, &conn->request);
            }
        }
        else if (status == MK_HTTP_PARSER_ERROR) {
            opentelemetry_prot_handle_error(ctx, conn, &conn->session, &conn->request);

            /* Reinitialize the parser so the next request is properly
             * handled, the additional memset intends to wipe any left over data
             * from the headers parsed in the previous request.
             */
            memset(&conn->session.parser, 0, sizeof(struct mk_http_parser));
            mk_http_parser_init(&conn->session.parser);
            opentelemetry_conn_request_init(&conn->session, &conn->request);
        }

        /* FIXME: add Protocol handler here */
        return bytes;
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        opentelemetry_conn_del(conn);
        return -1;
    }

    return 0;

}

static void opentelemetry_conn_session_init(struct mk_http_session *session,
                                            struct mk_server *server,
                                            int client_fd)
{
    /* Alloc memory for node */
    session->_sched_init = MK_TRUE;
    session->pipelined   = MK_FALSE;
    session->counter_connections = 0;
    session->close_now = MK_FALSE;
    session->status = MK_REQUEST_STATUS_INCOMPLETE;
    session->server = server;
    session->socket = client_fd;

    /* creation time in unix time */
    session->init_time = time(NULL);

    session->channel = mk_channel_new(MK_CHANNEL_SOCKET, session->socket);
    session->channel->io = session->server->network;

    /* Init session request list */
    mk_list_init(&session->request_list);

    /* Initialize the parser */
    mk_http_parser_init(&session->parser);
}

static void opentelemetry_conn_request_init(struct mk_http_session *session,
                                            struct mk_http_request *request)
{
    memset(request, 0, sizeof(struct mk_http_request));

    mk_http_request_init(session, request, session->server);

    request->in_headers.type        = MK_STREAM_IOV;
    request->in_headers.dynamic     = MK_FALSE;
    request->in_headers.cb_consumed = NULL;
    request->in_headers.cb_finished = NULL;
    request->in_headers.stream      = &request->stream;

    mk_list_add(&request->in_headers._head, &request->stream.inputs);

    request->session = session;
}

struct http_conn *opentelemetry_conn_add(int fd, struct flb_opentelemetry *ctx)
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
    event->handler = opentelemetry_conn_event;

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
    opentelemetry_conn_session_init(&conn->session, ctx->server, conn->fd);

    /* Initialize HTTP Request: this is the initial request and it will be reinitialized
     * automatically after the request is handled so it can be used for the next one.
     */
    opentelemetry_conn_request_init(&conn->session, &conn->request);

    /* Link connection node to parent context list */
    mk_list_add(&conn->_head, &ctx->connections);
    return conn;
}

int opentelemetry_conn_del(struct http_conn *conn)
{
    struct flb_opentelemetry *ctx;

    ctx = conn->ctx;

    if (conn->session.channel != NULL) {
        mk_channel_release(conn->session.channel);
    }

    mk_event_del(ctx->evl, &conn->event);
    mk_list_del(&conn->_head);
    flb_socket_close(conn->fd);
    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}

void opentelemetry_conn_release_all(struct flb_opentelemetry *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct http_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct http_conn, _head);
        opentelemetry_conn_del(conn);
    }
}
