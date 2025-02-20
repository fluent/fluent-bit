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
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_downstream.h>

#include "prom_rw.h"
#include "prom_rw_conn.h"
#include "prom_rw_prot.h"

static void prom_rw_conn_request_init(struct mk_http_session *session,
                                      struct mk_http_request *request);


static int prom_rw_conn_buffer_realloc(struct flb_prom_remote_write *ctx,
                                       struct prom_remote_write_conn *conn, size_t size)
{
    char *tmp;

    /* Perform realloc */
    tmp = flb_realloc(conn->buf_data, size);
    if (!tmp) {
        flb_errno();
        flb_plg_error(ctx->ins, "could not perform realloc for size %zu", size);
        return -1;
    }

    /* Update buffer info */
    conn->buf_data = tmp;
    conn->buf_size = size;

    /* Keep NULL termination */
    conn->buf_data[conn->buf_len] = '\0';

    /* Reset parser state */
    mk_http_parser_init(&conn->session.parser);

    return 0;
}

static int prom_rw_conn_event(void *data)
{
    int ret;
    int status;
    size_t size;
    ssize_t available;
    ssize_t bytes;
    char *request_end;
    size_t request_len;
    struct prom_remote_write_conn *conn;
    struct mk_event *event;
    struct flb_prom_remote_write *ctx;
    struct flb_connection *connection;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    event = &connection->event;

    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->buffer_chunk_size > ctx->buffer_max_size) {
                flb_plg_trace(ctx->ins,
                              "fd=%i incoming data exceed limit (%zu KB)",
                              event->fd, (ctx->buffer_max_size / 1024));
                prom_rw_conn_del(conn);
                return -1;
            }

            size = conn->buf_size + ctx->buffer_chunk_size;
            ret = prom_rw_conn_buffer_realloc(ctx, conn, size);
            if (ret == -1) {
                flb_errno();
                prom_rw_conn_del(conn);
                return -1;
            }

            flb_plg_trace(ctx->ins, "fd=%i buffer realloc %i -> %zu",
                          event->fd, conn->buf_size, size);

            available = (conn->buf_size - conn->buf_len) - 1;
        }

        /* Read data */
        bytes = flb_io_net_read(connection,
                                (void *) &conn->buf_data[conn->buf_len],
                                available);

        if (bytes <= 0) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            prom_rw_conn_del(conn);
            return -1;
        }

        flb_plg_trace(ctx->ins, "read()=%zi pre_len=%i now_len=%zi",
                      bytes, conn->buf_len, conn->buf_len + bytes);
        conn->buf_len += bytes;
        conn->buf_data[conn->buf_len] = '\0';

        status = mk_http_parser(&conn->request, &conn->session.parser,
                                conn->buf_data, conn->buf_len, conn->session.server);

        if (status == MK_HTTP_PARSER_OK) {
            /* Do more logic parsing and checks for this request */
            prom_rw_prot_handle(ctx, conn, &conn->session, &conn->request);

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
                prom_rw_conn_request_init(&conn->session, &conn->request);
            }
        }
        else if (status == MK_HTTP_PARSER_ERROR) {
            prom_rw_prot_handle_error(ctx, conn, &conn->session, &conn->request);

            /* Reinitialize the parser so the next request is properly
             * handled, the additional memset intends to wipe any left over data
             * from the headers parsed in the previous request.
             */
            memset(&conn->session.parser, 0, sizeof(struct mk_http_parser));
            mk_http_parser_init(&conn->session.parser);
            prom_rw_conn_request_init(&conn->session, &conn->request);
        }

        return bytes;
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        prom_rw_conn_del(conn);
        return -1;
    }

    return 0;

}

static void prom_rw_conn_session_init(struct mk_http_session *session,
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

static void prom_rw_conn_request_init(struct mk_http_session *session,
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

struct prom_remote_write_conn *prom_rw_conn_add(struct flb_connection *connection,
                                                struct flb_prom_remote_write *ctx)
{
    struct prom_remote_write_conn *conn;
    int                            ret;

    conn = flb_calloc(1, sizeof(struct prom_remote_write_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }
    conn->connection = connection;

    /* Set data for the event-loop */
    MK_EVENT_NEW(&connection->event);

    connection->user_data     = conn;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = prom_rw_conn_event;

    /* Connection info */
    conn->ctx     = ctx;
    conn->buf_len = 0;

    conn->buf_data = flb_malloc(ctx->buffer_chunk_size);
    if (!conn->buf_data) {
        flb_errno();
        flb_plg_error(ctx->ins, "could not allocate new connection");
        flb_free(conn);
        return NULL;
    }
    conn->buf_size = ctx->buffer_chunk_size;

    /* Register instance into the event loop */
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

    /* Initialize HTTP Session: this is a custom context for Monkey HTTP */
    prom_rw_conn_session_init(&conn->session, ctx->server, connection->fd);

    /* Initialize HTTP Request: this is the initial request and it will be reinitialized
     * automatically after the request is handled so it can be used for the next one.
     */
    prom_rw_conn_request_init(&conn->session, &conn->request);

    /* Link connection node to parent context list */
    mk_list_add(&conn->_head, &ctx->connections);
    return conn;
}

int prom_rw_conn_del(struct prom_remote_write_conn *conn)
{
    if (conn->session.channel != NULL) {
        mk_channel_release(conn->session.channel);
    }

    /* The downstream unregisters the file descriptor from the event-loop
     * so there's nothing to be done by the plugin
     */
    flb_downstream_conn_release(conn->connection);

    mk_list_del(&conn->_head);

    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}

void prom_rw_conn_release_all(struct flb_prom_remote_write *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct prom_remote_write_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct prom_remote_write_conn, _head);
        prom_rw_conn_del(conn);
    }
}
