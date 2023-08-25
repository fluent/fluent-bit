/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_version.h>
#include "prom.h"
#include "prom_http_conn.h"
#include "prom_metrics.h"

static int prom_http_io_net_write_response(struct prom_http_conn *conn, int http_status, 
                                           char* content, int content_len, 
                                           flb_sds_t content_type)
{
    size_t sent;
    flb_sds_t response;
    size_t response_len;
    flb_sds_t server_line;
    flb_sds_t status_line;
    flb_sds_t content_type_line;
    flb_sds_t content_line;

    // TODO: I think this is everything?
    if (http_status == 200) {
        status_line = flb_sds_create("HTTP/1.1 200 OK\r\n");
    } else if (http_status == 404) {
        status_line = flb_sds_create("HTTP/1.1 404 Not Found\r\n");
    } else if (http_status == 400) {
        status_line = flb_sds_create("HTTP/1.1 400 Bad Request\r\n");
    } else if (http_status == 500) {
        status_line = flb_sds_create("HTTP/1.1 500 Internal Server Error\r\n");
    }
    if (!status_line) {
        return -1;
    }

    if (content_type) {
        content_type_line = flb_sds_create_size(256);
        if (!content_type_line) {
            return -1;
        }
        content_type_line = flb_sds_create("Content-Type: text/plain\r\n");
        flb_sds_printf(&content_type_line, "Content-Type: %s\r\n", content_type);
    }
    else {
        content_type_line = flb_sds_create("Content-Type: text/plain\r\n");
    }
    
    server_line = flb_sds_create_size(256);
    if (!server_line) {
        return -1;
    }
    flb_sds_printf(&server_line, "Server: Fluent Bit v%s\r\n", FLB_VERSION_STR);

    if (content != NULL) {
        content_line = flb_sds_create_size(256);
        if (!content_line) {
            return -1;
        }

        flb_sds_printf(&content_line, "Content-Length: %i\r\n\r\n%s",
                       content_len, content);
    }
    else {
        content_line = flb_sds_create("Content-Length: 0\r\n\r\n");
    }
    if(!content_line) {
        return -1;
    }

    response = flb_sds_create_size(256);
    if (!response) {
        return -1;
    }
    flb_sds_printf(&response, "%s%s%s", status_line, server_line, content_line);
    response_len = flb_sds_len(response);

    flb_io_net_write(conn->connection,
                     (void *) response,
                     response_len,
                     &sent);
    //TODO: add if(sent < len) return -1 maybe?
    return 0;
}

static int match_uri(char *request_uri, char *match_uri)
{
    size_t len_uri;
    size_t len_match;
    len_uri = strlen(request_uri); 
    len_match = strlen(match_uri);
    return (len_uri >= len_match) && !memcmp(request_uri, match_uri, len_match);
}

static int prom_http_send_root(struct prom_http_conn *conn)
{
    flb_sds_t content = flb_sds_create("Fluent Bit Prometheus Exporter\n");
    return prom_http_io_net_write_response(conn, 200, 
                                           content, flb_sds_len(content), NULL);
}

static int prom_http_send_metrics(struct prom_http_conn *conn)
{
    int ret;
    struct prom_metrics_buf *buf;
    flb_sds_t content_type;
    
    buf = prom_metrics_get_latest();
    if (!buf) {
        prom_http_io_net_write_response(conn, 404, NULL, 0, NULL);
        return -1;
    }

    buf->users++;

    content_type = flb_sds_create_len(FLB_HS_CONTENT_TYPE_PROMETHEUS_STR, 
                                      FLB_HS_CONTENT_TYPE_PROMETHEUS_LEN);
    ret = prom_http_io_net_write_response(conn, 200, buf->buf_data, buf->buf_size, content_type);

    buf->users--;

    return ret;
}

static inline int mk_http_point_header(mk_ptr_t *h,
                                       struct mk_http_parser *parser, int key)
{
    struct mk_http_header *header;

    header = &parser->headers[key];
    if (header->type == key) {
        h->data = header->val.data;
        h->len  = header->val.len;
        return 0;
    }
    else {
        h->data = NULL;
        h->len  = -1;
    }

    return -1;
}


static int prom_http_req_handle(struct prom_exporter *ctx, struct prom_http_conn *conn,
                         struct mk_http_session *session,
                         struct mk_http_request *request)
{
    int ret;
    char *uri;
    flb_sds_t content;

    if (request->uri.data[0] != '/') {
        content = flb_sds_create("error: invalid request\n");
        prom_http_io_net_write_response(conn, 400, content, flb_sds_len(content), NULL);
        return -1;
    }

    uri = mk_utils_url_decode(request->uri);
    if (!uri) {
        uri = mk_mem_alloc_z(request->uri.len + 1);
        if (!uri) {
            return -1;
        }
        memcpy(uri, request->uri.data, request->uri.len);
        uri[request->uri.len] = '\0';
    }

    /* Header: Host */
    mk_http_point_header(&request->host, &session->parser, MK_HEADER_HOST);
    /* Header: Connection */
    mk_http_point_header(&request->connection, &session->parser, MK_HEADER_CONNECTION);
    /* HTTP/1.1 needs Host header */
    if (!request->host.data && request->protocol == MK_HTTP_PROTOCOL_11) {
        return -1;
    }

    /* Should we close the session after this request? */
    mk_http_keepalive_check(session, request, ctx->mk_ctx->server);

    if (request->method != MK_METHOD_GET) {
        content = flb_sds_create("error: only GET method is supported\n");
        prom_http_io_net_write_response(conn, 400, 
                                        content, flb_sds_len(content), NULL);
        return -1;
    }

    // Check if the request is to the "/metrics" endpoint
    if (match_uri(uri, "/metrics"))
    {
        ret = prom_http_send_metrics(conn);
    }
    else {
        ret = prom_http_send_root(conn);
    }

    flb_free(uri);
    return ret;
}

static int prom_http_req_handle_error(struct prom_exporter *ctx, struct prom_http_conn *conn,
                                struct mk_http_session *session,
                                struct mk_http_request *request)
{
    flb_sds_t content = "error: invalid request\n";
    prom_http_io_net_write_response(conn, 400, content, flb_sds_len(content), NULL);
    return -1;
}

static void prom_http_conn_session_init(struct mk_http_session *session,
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

static void prom_http_conn_request_init(struct mk_http_session *session,
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

int prom_http_conn_event(void *data) 
{
    int status;
    size_t size;
    ssize_t available;
    ssize_t bytes;
    char *tmp;
    char *request_end;
    size_t request_len;
    struct flb_connection *connection;
    struct prom_http_conn *conn;
    struct mk_event *event;
    struct prom_exporter *ctx;

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
                            event->fd, (ctx->buffer_max_size / 1024)); // TODO: Actually decide on limit
                prom_http_conn_destroy(conn);
                return -1;
            }

            size = conn->buf_size + ctx->buffer_chunk_size;
            tmp = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                flb_errno();
                return -1;
            }
            flb_plg_trace(ctx->ins, "fd=%i buffer realloc %i -> %zu",
                          event->fd, conn->buf_size, size);
            
            conn->buf_data = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len) - 1;
        }

        /* Read data */
        bytes = flb_io_net_read(connection,
                                (void *) &conn->buf_data[conn->buf_len],
                                available);

        if (bytes <= 0) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            prom_http_conn_destroy(conn);
            return -1;
        }

        flb_plg_trace(ctx->ins, "read()=%zi pre_len=%i now_len=%zi",
                        bytes, conn->buf_len, conn->buf_len + bytes);
        conn->buf_len += bytes;
        conn->buf_data[conn->buf_len] = '\0';

        status = mk_http_parser(&conn->request, &conn->session.parser,
                                conn->buf_data, conn->buf_len, conn->session.server);

        if (status == MK_HTTP_PARSER_OK) {
            prom_http_req_handle(ctx, conn, &conn->session, &conn->request);

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
                memset(&conn->session.parser, 0, sizeof(mk_http_parser));
                mk_http_parser_init(&conn->session.parser);
                prom_http_conn_request_init(&conn->session, &conn->request);
            }
        }
        else if (status == MK_HTTP_PARSER_ERROR) {
            prom_http_req_handle_error(ctx, conn, &conn->session, &conn->request);
            
            /* Reinitialize the parser so the next request is properly
                * handled, the additional memset intends to wipe any left over data
                * from the headers parsed in the previous request.
                */
            memset(&conn->session.parser, 0, sizeof(mk_http_parser));
            mk_http_parser_init(&conn->session.parser);
            prom_http_conn_request_init(&conn->session, &conn->request);
        }

        /* FIXME: add Protocol handler here */
        return bytes;
    }

    flb_info("hi closing now");
    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        prom_http_conn_destroy(conn);
        return -1;
    }

    return 0;
}

struct prom_http_conn *prom_http_conn_create(struct flb_connection *conn, 
                                             struct prom_exporter *ctx)
{
    struct prom_http_conn *prom_conn;
    int ret; 

    prom_conn = flb_calloc(1, sizeof(struct prom_http_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    prom_conn->connection = conn;

    MK_EVENT_NEW(&conn->event);
    conn->user_data = prom_conn;
    conn->event.type = FLB_ENGINE_EV_CUSTOM;
    conn->event.handler = prom_http_conn_event;

    prom_conn->ctx = ctx;
    prom_conn->buf_len = 0;

    // TODO: idk if this should be using buffer_chunk_size...
    prom_conn->buf_data = flb_malloc(ctx->buffer_chunk_size);
    if (!prom_conn->buf_data) {
        flb_errno();

        flb_plg_error(ctx->ins, "could not allocate new connection");
        flb_free(prom_conn);

        return NULL;
    }
    prom_conn->buf_size = ctx->buffer_chunk_size;

    /* Register connection instance into the event loop. */
    ret = mk_event_add(flb_engine_evl_get(),
                       conn->fd,
                       FLB_ENGINE_EV_CUSTOM,
                       MK_EVENT_READ,
                       &conn->event);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");

        flb_free(prom_conn->buf_data);
        flb_free(prom_conn);

        return NULL;
    }

    prom_http_conn_session_init(&prom_conn->session, ctx->mk_ctx->server, 
                                prom_conn->connection->fd);
    prom_http_conn_request_init(&prom_conn->session, &prom_conn->request);

    /* Link connection node to parent context list */
    mk_list_add(&prom_conn->_head, &ctx->connections);

    return prom_conn;
}

int prom_http_conn_destroy(struct prom_http_conn *conn) 
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

void prom_http_conn_release_all(struct prom_exporter *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct prom_http_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct prom_http_conn, _head);
        prom_http_conn_destroy(conn);
    }
}
