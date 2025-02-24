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
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_snappy.h>

#include <monkey/monkey.h>
#include <fluent-bit/http_server/flb_http_server.h>

#include <monkey/mk_core.h>
#include <cmetrics/cmt_decode_prometheus_remote_write.h>

#include "prom_rw.h"
#include "prom_rw_conn.h"

static int send_response(struct flb_input_instance *in,
                         struct prom_remote_write_conn *conn,
                         int http_status, char *message)
{
    int len;
    flb_sds_t out;
    size_t sent;
    ssize_t bytes;
    int result;

    out = flb_sds_create_size(256);
    if (!out) {
        return -1;
    }

    if (message) {
        len = strlen(message);
    }
    else {
        len = 0;
    }

    if (http_status == 201) {
        flb_sds_printf(&out,
                       "HTTP/1.1 201 Created \r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "Content-Length: 0\r\n\r\n",
                       FLB_VERSION_STR);
    }
    else if (http_status == 200) {
        flb_sds_printf(&out,
                       "HTTP/1.1 200 OK\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "Content-Length: 0\r\n\r\n",
                       FLB_VERSION_STR);
    }
    else if (http_status == 204) {
        flb_sds_printf(&out,
                       "HTTP/1.1 204 No Content\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "\r\n",
                       FLB_VERSION_STR);
    }
    else if (http_status == 400) {
        flb_sds_printf(&out,
                       "HTTP/1.1 400 Bad Request\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "Content-Length: %i\r\n\r\n%s",
                       FLB_VERSION_STR,
                       len, message);
    }

    /* We should check the outcome of this operation */
    bytes = flb_io_net_write(conn->connection,
                             (void *) out,
                             flb_sds_len(out),
                             &sent);

    if (bytes == -1) {
        flb_plg_error(in, "cannot send response");

        result = -1;
    }
    else {
        result = 0;
    }

    flb_sds_destroy(out);

    return result;
}

static int process_payload_metrics(struct flb_prom_remote_write *ctx,
                                   struct prom_remote_write_conn *conn,
                                   flb_sds_t tag,
                                   struct mk_http_session *session,
                                   struct mk_http_request *request)
{
    struct cmt *context;
    int         result;

    result = cmt_decode_prometheus_remote_write_create(&context,
                                                       request->data.data,
                                                       request->data.len);

    if (result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        result = flb_input_metrics_append(ctx->ins, NULL, 0, context);

        cmt_decode_prometheus_remote_write_destroy(context);
        if (result != 0) {
            flb_plg_debug(ctx->ins, "could not ingest metrics : %d", result);
            return -1;
        }

        return 0;
    }

    return -1;
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

static int uncompress_snappy(char **output_buffer,
                             size_t *output_size,
                             char *input_buffer,
                             size_t input_size)
{
    int ret;

    ret = flb_snappy_uncompress_framed_data(input_buffer,
                                            input_size,
                                            output_buffer,
                                            output_size);

    if (ret != 0) {
        flb_error("[opentelemetry] snappy decompression failed");

        return -1;
    }

    return 1;
}

static int uncompress_gzip(char **output_buffer,
                           size_t *output_size,
                           char *input_buffer,
                           size_t input_size)
{
    int ret;

    ret = flb_gzip_uncompress(input_buffer,
                              input_size,
                              (void *) output_buffer,
                              output_size);

    if (ret == -1) {
        flb_error("[opentelemetry] gzip decompression failed");

        return -1;
    }

    return 1;
}

int prom_rw_prot_uncompress(struct mk_http_session *session,
                            struct mk_http_request *request,
                            char **output_buffer,
                            size_t *output_size)
{
    struct mk_http_header *header;
    size_t                 index;

    *output_buffer = NULL;
    *output_size = 0;

    for (index = 0;
         index < session->parser.headers_extra_count;
         index++) {
        header = &session->parser.headers_extra[index];

        if (strncasecmp(header->key.data, "Content-Encoding", 16) == 0) {
            if (strncasecmp(header->val.data, "gzip", 4) == 0) {
                return uncompress_gzip(output_buffer,
                                       output_size,
                                       request->data.data,
                                       request->data.len);
            }
            else if (strncasecmp(header->val.data, "snappy", 6) == 0) {
                return uncompress_snappy(output_buffer,
                                         output_size,
                                         request->data.data,
                                         request->data.len);
            }
            else {
                return -2;
            }
        }
    }

    return 0;
}


/*
 * Handle an incoming request. It performs extra checks over the request, if
 * everything is OK, it enqueue the incoming payload.
 */
int prom_rw_prot_handle(struct flb_prom_remote_write *ctx,
                        struct prom_remote_write_conn *conn,
                        struct mk_http_session *session,
                        struct mk_http_request *request)
{
    int i;
    int ret = -1;
    int len;
    char *uri;
    char *qs;
    off_t diff;
    flb_sds_t tag;
    struct mk_http_header *header;
    char *original_data;
    size_t original_data_size;
    char *uncompressed_data;
    size_t uncompressed_data_size;

    if (request->uri.data[0] != '/') {
        send_response(ctx->ins, conn, 400, "error: invalid request\n");
        return -1;
    }

    /* Decode URI */
    uri = mk_utils_url_decode(request->uri);
    if (!uri) {
        uri = mk_mem_alloc_z(request->uri.len + 1);
        if (!uri) {
            return -1;
        }
        memcpy(uri, request->uri.data, request->uri.len);
        uri[request->uri.len] = '\0';
    }

    if (ctx->uri != NULL && strcmp(uri, ctx->uri) != 0) {
        send_response(ctx->ins, conn, 400, "error: invalid endpoint\n");
        mk_mem_free(uri);

        return -1;
    }

    /* Try to match a query string so we can remove it */
    qs = strchr(uri, '?');
    if (qs) {
        /* remove the query string part */
        diff = qs - uri;
        uri[diff] = '\0';
    }

    /* Compose the query string using the URI */
    len = strlen(uri);

    if (ctx->tag_from_uri != FLB_TRUE) {
        tag = flb_sds_create(ctx->ins->tag);
    }
    else {
        tag = flb_sds_create_size(len);
        if (!tag) {
            mk_mem_free(uri);
            return -1;
        }

        /* New tag skipping the URI '/' */
        flb_sds_cat_safe(&tag, uri + 1, len - 1);

        /* Sanitize, only allow alphanum chars */
        for (i = 0; i < flb_sds_len(tag); i++) {
            if (!isalnum(tag[i]) && tag[i] != '_' && tag[i] != '.') {
                tag[i] = '_';
            }
        }
    }

    /* Check if we have a Host header: Hostname ; port */
    mk_http_point_header(&request->host, &session->parser, MK_HEADER_HOST);

    /* Header: Connection */
    mk_http_point_header(&request->connection, &session->parser,
                         MK_HEADER_CONNECTION);

    /* HTTP/1.1 needs Host header */
    if (!request->host.data && request->protocol == MK_HTTP_PROTOCOL_11) {
        flb_sds_destroy(tag);
        mk_mem_free(uri);
        return -1;
    }

    /* Should we close the session after this request ? */
    mk_http_keepalive_check(session, request, ctx->server);

    /* Content Length */
    header = &session->parser.headers[MK_HEADER_CONTENT_LENGTH];
    if (header->type == MK_HEADER_CONTENT_LENGTH) {
        request->_content_length.data = header->val.data;
        request->_content_length.len  = header->val.len;
    }
    else {
        request->_content_length.data = NULL;
    }

    mk_http_point_header(&request->content_type, &session->parser, MK_HEADER_CONTENT_TYPE);

    if (request->method != MK_METHOD_POST) {
        flb_sds_destroy(tag);
        mk_mem_free(uri);
        send_response(ctx->ins, conn, 400, "error: invalid HTTP method\n");
        return -1;
    }

    if (request->data.data == NULL || request->data.len <= 0) {
        flb_sds_destroy(tag);
        mk_mem_free(uri);
        send_response(ctx->ins, conn, 400, "error: no payload found\n");
        return -1;
    }

    original_data = request->data.data;
    original_data_size = request->data.len;

    ret = prom_rw_prot_uncompress(session, request,
                                  &uncompressed_data,
                                  &uncompressed_data_size);

    if (ret > 0) {
        request->data.data = uncompressed_data;
        request->data.len = uncompressed_data_size;
    }

    if (ctx->uri != NULL && strcmp(uri, ctx->uri) == 0) {
        ret = process_payload_metrics(ctx, conn, tag, session, request);
    }
    else {
        ret = process_payload_metrics(ctx, conn, tag, session, request);
    }

    if (uncompressed_data != NULL) {
        flb_free(uncompressed_data);
    }

    request->data.data = original_data;
    request->data.len = original_data_size;

    mk_mem_free(uri);
    flb_sds_destroy(tag);

    if (ret == -1) {
        send_response(ctx->ins, conn, 400, "error: invalid request\n");
        return -1;
    }

    send_response(ctx->ins, conn, ctx->successful_response_code, NULL);
    return ret;
}

/*
 * Handle an incoming request which has resulted in an http parser error.
 */
int prom_rw_prot_handle_error(
        struct flb_prom_remote_write *ctx,
        struct prom_remote_write_conn *conn,
        struct mk_http_session *session,
        struct mk_http_request *request)
{
    send_response(ctx->ins, conn, 400, "error: invalid request\n");
    return -1;
}


/* New gen HTTP server */
static int send_response_ng(struct flb_http_response *response,
                            int http_status,
                            char *message)
{
    flb_http_response_set_status(response, http_status);

    if (http_status == 201) {
        flb_http_response_set_message(response, "Created");
    }
    else if (http_status == 200) {
        flb_http_response_set_message(response, "OK");
    }
    else if (http_status == 204) {
        flb_http_response_set_message(response, "No Content");
    }
    else if (http_status == 400) {
        flb_http_response_set_message(response, "Bad Request");
    }

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int process_payload_metrics_ng(struct flb_prom_remote_write *ctx,
                                      flb_sds_t tag,
                                      struct flb_http_request *request,
                                      struct flb_http_response *response)
{
    struct cmt *context;
    int         result;

    result = cmt_decode_prometheus_remote_write_create(&context,
                                                       request->body,
                                                       cfl_sds_len(request->body));

    if (result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        result = flb_input_metrics_append(ctx->ins, NULL, 0, context);

        if (result != 0) {
            flb_plg_debug(ctx->ins, "could not ingest metrics : %d", result);
        }

        cmt_decode_prometheus_remote_write_destroy(context);
    }

    return 0;
}

int prom_rw_prot_handle_ng(struct flb_http_request *request,
                           struct flb_http_response *response)
{
    struct flb_prom_remote_write *context;
    int                           result;

    context = (struct flb_prom_remote_write *) response->stream->user_data;

    if (request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    /* ToDo: Fix me */
    /* HTTP/1.1 needs Host header */
    if (request->protocol_version >= HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {
        return -1;
    }

    if (request->method != HTTP_METHOD_POST) {
        send_response_ng(response, 400, "error: invalid HTTP method\n");
        return -1;
    }

    /* check content-length */
    if (request->content_length <= 0) {
        send_response_ng(response, 400, "error: invalid content-length\n");
        return -1;
    }

    if (request->body == NULL) {
        send_response_ng(response, 400, "error: invalid payload\n");
        return -1;
    }

    if (context->uri != NULL && strcmp(request->path, context->uri) == 0) {
        result = process_payload_metrics_ng(context, context->ins->tag, request, response);
    }
    else {
        result = process_payload_metrics_ng(context, context->ins->tag, request, response);
    }

    send_response_ng(response, context->successful_response_code, NULL);

    return result;
}
