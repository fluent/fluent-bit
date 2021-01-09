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
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include <monkey/monkey.h>
#include <monkey/mk_core.h>

#include "http.h"
#include "http_conn.h"

#define HTTP_CONTENT_JSON  0

static int send_response(struct http_conn *conn, int http_status, char *message)
{
    int len;
    flb_sds_t out;

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
    else if (http_status == 400) {
        flb_sds_printf(&out,
                       "HTTP/1.1 400 Forbidden\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "Content-Length: %i\r\n\r\n%s",
                       FLB_VERSION_STR,
                       len, message);
    }

    write(conn->fd, out, flb_sds_len(out));
    flb_sds_destroy(out);
    return 0;
}

int process_pack(struct flb_http *ctx, flb_sds_t tag, char *buf, size_t size)
{
    size_t off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_unpacked result;
    struct flb_time tm;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    flb_time_get(&tm);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_MAP) {
            flb_plg_warn(ctx->ins, "skip record from invalid type: %i",
                         result.data.type);
            continue;
        }

        /* Pack record with timestamp */
        msgpack_pack_array(&mp_pck, 2);
        flb_time_append_to_msgpack(&tm, &mp_pck, 0);
        msgpack_pack_object(&mp_pck, result.data);
    }

    /* Ingest real record into the engine */
    if (tag) {
        flb_input_chunk_append_raw(ctx->ins, tag, flb_sds_len(tag),
                                   mp_sbuf.data, mp_sbuf.size);
    }
    else {
        /* use default plugin Tag (it internal name, e.g: http.0 */
        flb_input_chunk_append_raw(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    }
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static ssize_t parse_payload_json(struct flb_http *ctx, flb_sds_t tag,
                                  char *payload, size_t size)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "JSON data is incomplete, skipping");
        return -1;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    process_pack(ctx, tag, pack, out_size);
    flb_free(pack);

    return 0;
}

static int process_payload(struct flb_http *ctx, struct http_conn *conn,
                           flb_sds_t tag,
                           struct mk_http_session *session,
                           struct mk_http_request *request)
{
    int type = -1;
    struct mk_http_header *header;

    header = &session->parser.headers[MK_HEADER_CONTENT_TYPE];
    if (header->key.data == NULL) {
        send_response(conn, 400, "error: header 'Content-Type' is not set\n");
        return -1;
    }

    if (header->val.len == 16 &&
        strncasecmp(header->val.data, "application/json", 16) == 0) {
        type = HTTP_CONTENT_JSON;
    }

    if (type == -1) {
        send_response(conn, 400, "error: invalid 'Content-Type'\n");
        return -1;
    }

    if (request->data.len <= 0) {
        send_response(conn, 400, "error: no payload found\n");
        return -1;
    }

    if (type == HTTP_CONTENT_JSON) {
        parse_payload_json(ctx, tag, request->data.data, request->data.len);
    }

    return 0;
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

/*
 * Handle an incoming request. It perform extra checks over the request, if
 * everything is OK, it enqueue the incoming payload.
 */
int http_prot_handle(struct flb_http *ctx, struct http_conn *conn,
                     struct mk_http_session *session,
                     struct mk_http_request *request)
{
    int i;
    int ret;
    int len;
    char *uri;
    char *qs;
    off_t diff;
    flb_sds_t tag;
    struct mk_http_header *header;

    if (request->uri.data[0] != '/') {
        send_response(conn, 400, "error: invalid request\n");
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

    /* Try to match a query string so we can remove it */
    qs = strchr(uri, '?');
    if (qs) {
        /* remove the query string part */
        diff = qs - uri;
        uri[diff] = '\0';
    }

    /* Compose the query string using the URI */
    len = strlen(uri);

    if (len == 1) {
        tag = NULL; /* use default tag */
    }
    else {
        tag = flb_sds_create_size(len);
        if (!tag) {
            mk_mem_free(uri);
            return -1;
        }

        /* New tag skipping the URI '/' */
        flb_sds_cat(tag, uri + 1, len - 1);

        /* Sanitize, only allow alphanum chars */
        for (i = 0; i < flb_sds_len(tag); i++) {
            if (!isalnum(tag[i]) && tag[i] != '_' && tag[i] != '.') {
                tag[i] = '_';
            }
        }
    }

    mk_mem_free(uri);

    /* Check if we have a Host header: Hostname ; port */
    mk_http_point_header(&request->host, &session->parser, MK_HEADER_HOST);

    /* Header: Connection */
    mk_http_point_header(&request->connection, &session->parser,
                         MK_HEADER_CONNECTION);

    /* HTTP/1.1 needs Host header */
    if (!request->host.data && request->protocol == MK_HTTP_PROTOCOL_11) {
        flb_sds_destroy(tag);
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

    if (request->method != MK_METHOD_POST) {
        flb_sds_destroy(tag);
        send_response(conn, 400, "error: invalid HTTP method\n");
        return -1;
    }

    ret = process_payload(ctx, conn, tag, session, request);
    flb_sds_destroy(tag);
    send_response(conn, 201, NULL);
    return ret;
}
