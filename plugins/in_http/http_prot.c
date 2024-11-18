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

#include <monkey/monkey.h>
#include <monkey/mk_core.h>

#include "http.h"
#include "http_conn.h"

#define HTTP_CONTENT_JSON       0
#define HTTP_CONTENT_URLENCODED 1

static inline char hex2nibble(char c)
{
    if ((c >= 0x30) && (c <= '9')) {
        return c - 0x30;
    }
    // 0x30-0x39 are digits, 0x41-0x46 A-F,
    // so there is a gap at 0x40
    if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A') + 10;
    }
    if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a') + 10;
    }
    return 0;
}

static int sds_uri_decode(flb_sds_t s)
{
    char buf[1024];
    char *optr;
    char *iptr;


    for (optr = buf, iptr = s; iptr < s + flb_sds_len(s) && optr-buf < sizeof(buf); iptr++) {
        if (*iptr == '%') {
            if (iptr+2 > (s + flb_sds_len(s))) {
                return -1;
            }
            *optr++ = hex2nibble(*(iptr+1)) << 4 | hex2nibble(*(iptr+2));
            iptr+=2;
        }
        else if (*iptr == '+') {
            *optr++ = ' ';
        }
        else {
            *optr++ = *iptr;
        }
    }

    memcpy(s, buf, optr-buf);
    s[optr-buf] = '\0';
    flb_sds_len_set(s, (optr-buf));

    return 0;
}

static int send_response(struct http_conn *conn, int http_status, char *message)
{
    struct flb_http *context;
    size_t           sent;
    int              len;
    flb_sds_t        out;

    context = (struct flb_http *) conn->ctx;

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
                       "%s"
                       "Content-Length: 0\r\n\r\n",
                       FLB_VERSION_STR,
                       context->success_headers_str);
    }
    else if (http_status == 200) {
        flb_sds_printf(&out,
                       "HTTP/1.1 200 OK\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "%s"
                       "Content-Length: 0\r\n\r\n",
                       FLB_VERSION_STR,
                       context->success_headers_str);
    }
    else if (http_status == 204) {
        flb_sds_printf(&out,
                       "HTTP/1.1 204 No Content\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "%s"
                       "\r\n\r\n",
                       FLB_VERSION_STR,
                       context->success_headers_str);
    }
    else if (http_status == 400) {
        flb_sds_printf(&out,
                       "HTTP/1.1 400 Bad Request\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "Content-Length: %i\r\n\r\n%s",
                       FLB_VERSION_STR,
                       len, message);
    }

    /* We should check this operations result */
    flb_io_net_write(conn->connection,
                     (void *) out,
                     flb_sds_len(out),
                     &sent);

    flb_sds_destroy(out);

    return 0;
}

/* implements functionality to get tag from key in record */
static flb_sds_t tag_key(struct flb_http *ctx, msgpack_object *map)
{
    size_t map_size = map->via.map.size;
    msgpack_object_kv *kv;
    msgpack_object  key;
    msgpack_object  val;
    char *key_str = NULL;
    char *val_str = NULL;
    size_t key_str_size = 0;
    size_t val_str_size = 0;
    int j;
    int check = FLB_FALSE;
    int found = FLB_FALSE;
    flb_sds_t tag;

    kv = map->via.map.ptr;

    for(j=0; j < map_size; j++) {
        check = FLB_FALSE;
        found = FLB_FALSE;
        key = (kv+j)->key;
        if (key.type == MSGPACK_OBJECT_BIN) {
            key_str  = (char *) key.via.bin.ptr;
            key_str_size = key.via.bin.size;
            check = FLB_TRUE;
        }
        if (key.type == MSGPACK_OBJECT_STR) {
            key_str  = (char *) key.via.str.ptr;
            key_str_size = key.via.str.size;
            check = FLB_TRUE;
        }

        if (check == FLB_TRUE) {
            if (strncmp(ctx->tag_key, key_str, key_str_size) == 0) {
                val = (kv+j)->val;
                if (val.type == MSGPACK_OBJECT_BIN) {
                    val_str  = (char *) val.via.bin.ptr;
                    val_str_size = val.via.str.size;
                    found = FLB_TRUE;
                    break;
                }
                if (val.type == MSGPACK_OBJECT_STR) {
                    val_str  = (char *) val.via.str.ptr;
                    val_str_size = val.via.str.size;
                    found = FLB_TRUE;
                    break;
                }
            }
        }
    }

    if (found == FLB_TRUE) {
        tag = flb_sds_create_len(val_str, val_str_size);
        if (!tag) {
            flb_errno();
            return NULL;
        }
        return tag;
    }


    flb_plg_error(ctx->ins, "Could not find tag_key %s in record", ctx->tag_key);
    return NULL;
}

static int process_pack_record(struct flb_http *ctx, struct flb_time *tm,
                               flb_sds_t tag,
                               msgpack_object *record)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_timestamp(&ctx->log_encoder, tm);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_body_from_msgpack_object(
            &ctx->log_encoder,
            record);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    if (tag) {
        ret = flb_input_log_append(ctx->ins,
                                   tag,
                                   flb_sds_len(tag),
                                   ctx->log_encoder.output_buffer,
                                   ctx->log_encoder.output_length);
    }
    else {
        /* use default plugin Tag (it internal name, e.g: http.0 */
        ret = flb_input_log_append(ctx->ins, NULL, 0,
                                   ctx->log_encoder.output_buffer,
                                   ctx->log_encoder.output_length);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return 0;
}

int process_pack(struct flb_http *ctx, flb_sds_t tag, char *buf, size_t size)
{
    int ret;
    size_t off = 0;
    msgpack_unpacked result;
    struct flb_time tm;
    int i = 0;
    msgpack_object *obj;
    msgpack_object record;
    flb_sds_t tag_from_record = NULL;

    flb_time_get(&tm);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        obj = &result.data;

        if (result.data.type == MSGPACK_OBJECT_MAP) {
            tag_from_record = NULL;
            if (ctx->tag_key) {
                obj = &result.data;
                tag_from_record = tag_key(ctx, obj);
            }

            if (tag_from_record) {
                ret = process_pack_record(ctx, &tm, tag_from_record, obj);
                flb_sds_destroy(tag_from_record);
            }
            else if (tag) {
                ret = process_pack_record(ctx, &tm, tag, obj);
            }
            else {
                ret = process_pack_record(ctx, &tm, NULL, obj);
            }

            if (ret != 0) {
                goto log_event_error;
            }

            flb_log_event_encoder_reset(&ctx->log_encoder);
        }
        else if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            for (i = 0; i < obj->via.array.size; i++) {
                record = obj->via.array.ptr[i];

                tag_from_record = NULL;
                if (ctx->tag_key) {
                    tag_from_record = tag_key(ctx, &record);
                }

                if (tag_from_record) {
                    ret = process_pack_record(ctx, &tm, tag_from_record, &record);
                    flb_sds_destroy(tag_from_record);
                }
                else if (tag) {
                    ret = process_pack_record(ctx, &tm, tag, &record);
                }
                else {
                    ret = process_pack_record(ctx, &tm, NULL, &record);
                }

                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    goto log_event_error;
                }

                /* TODO : Optimize this
                 *
                 * This is wasteful, considering that we are emitting a series
                 * of records we should start and commit each one and then
                 * emit them all at once after the loop.
                 */

                flb_log_event_encoder_reset(&ctx->log_encoder);
            }

            break;
        }
        else {
            flb_plg_error(ctx->ins, "skip record from invalid type: %i",
                         result.data.type);

            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }

    msgpack_unpacked_destroy(&result);

    return 0;

log_event_error:
    msgpack_unpacked_destroy(&result);
    flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
    return ret;
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
        flb_plg_warn(ctx->ins, "error parsing JSON message, skipping");
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    ret = process_pack(ctx, tag, pack, out_size);
    flb_free(pack);

    return ret;
}

static ssize_t parse_payload_urlencoded(struct flb_http *ctx, flb_sds_t tag,
                                        char *payload, size_t size)
{
    int i;
    int idx = 0;
    int ret = -1;
    int len;
    struct mk_list *kvs;
    struct mk_list *head = NULL;
    struct mk_list *tmp;
    struct flb_split_entry *cur = NULL;
    char **keys = NULL;
    char **vals = NULL;
    char *sep;
    char *start;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;


    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    kvs = flb_utils_split(payload, '&', -1 );
    if (kvs == NULL) {
        goto split_error;
    }

    keys = flb_calloc(mk_list_size(kvs), sizeof(char *));
    if (keys == NULL) {
        goto keys_calloc_error;
    }

    vals = flb_calloc(mk_list_size(kvs), sizeof(char *));
    if (vals == NULL) {
        goto vals_calloc_error;
    }

    mk_list_foreach_safe(head, tmp, kvs) {
        cur = mk_list_entry(head, struct flb_split_entry, _head);
        if (cur->value[0] == '\n') {
            start = &cur->value[1];
        }
        else {
            start = cur->value;
        }

        if (!start || *start == '=' || strlen(start) == 0) {
            flb_utils_split_free_entry(cur);
            continue;
        }

        sep = strchr(start, '=');
        if (sep) {
            len = sep - start;
        }
        else {
            /* if no separator is found, just skip the content */
            flb_utils_split_free_entry(cur);
            continue;
        }

        keys[idx] = flb_sds_create_len(start, len);
        len++;

        if (start[len] == '\0') {
            vals[idx] = flb_sds_create("");
        }
        else {
            vals[idx] = flb_sds_create(start + len);
        }

        flb_sds_trim(keys[idx]);
        flb_sds_trim(vals[idx]);
        idx++;
    }

    if (mk_list_size(kvs) == 0) {
        goto decode_error;
    }

    msgpack_pack_map(&pck, mk_list_size(kvs));
    for (i = 0; i < idx; i++) {
        msgpack_pack_str(&pck, flb_sds_len(keys[i]));
        msgpack_pack_str_body(&pck, keys[i], flb_sds_len(keys[i]));

        if (sds_uri_decode(vals[i]) != 0) {
            goto decode_error;
        }
        else {
            msgpack_pack_str(&pck, flb_sds_len(vals[i]));
            msgpack_pack_str_body(&pck, vals[i], flb_sds_len(vals[i]));
        }
    }

    ret = process_pack(ctx, tag, sbuf.data, sbuf.size);

decode_error:
    for (idx = 0; idx < mk_list_size(kvs); idx++) {
        if (keys[idx]) {
            flb_sds_destroy(keys[idx]);
        }
        if (vals[idx]) {
            flb_sds_destroy(vals[idx]);
        }
    }
    flb_free(vals);
vals_calloc_error:
    flb_free(keys);
keys_calloc_error:
    flb_utils_split_free(kvs);
split_error:
    msgpack_sbuffer_destroy(&sbuf);
    return ret;
}

static int process_payload(struct flb_http *ctx, struct http_conn *conn,
                           flb_sds_t tag,
                           struct mk_http_session *session,
                           struct mk_http_request *request)
{
    int ret = -1;
    int type = -1;
    char *original_data;
    size_t original_data_size;
    char *out_chunked = NULL;
    size_t out_chunked_size;
    struct mk_http_header *header;

    header = &session->parser.headers[MK_HEADER_CONTENT_TYPE];
    if (header->key.data == NULL) {
        send_response(conn, 400, "error: header 'Content-Type' is not set\n");
        return -1;
    }

    if (((header->val.len == 16 && strncasecmp(header->val.data, "application/json", 16) == 0)) ||
        ((header->val.len > 16 && (strncasecmp(header->val.data, "application/json ", 17) == 0)) ||
        strncasecmp(header->val.data, "application/json;", 17) == 0)) {
        type = HTTP_CONTENT_JSON;
    }

    if (header->val.len == 33 &&
        strncasecmp(header->val.data, "application/x-www-form-urlencoded", 33) == 0) {
        type = HTTP_CONTENT_URLENCODED;
    }

    if (type == -1) {
        send_response(conn, 400, "error: invalid 'Content-Type'\n");
        return -1;
    }

    if (request->data.len <= 0 && !mk_http_parser_is_content_chunked(&session->parser)) {
        send_response(conn, 400, "error: no payload found\n");
        return -1;
    }

    /* content: check if the data comes in chunks (transfer-encoding: chunked) */
    if (mk_http_parser_is_content_chunked(&session->parser)) {
        ret = mk_http_parser_chunked_decode(&session->parser,
                                            conn->buf_data,
                                            conn->buf_len,
                                            &out_chunked,
                                            &out_chunked_size);

        if (ret == -1) {
            send_response(conn, 400, "error: invalid chunked data\n");
            return -1;
        }

        /* link the decoded data */
        original_data = request->data.data;
        original_data_size = request->data.len;

        request->data.data = out_chunked;
        request->data.len = out_chunked_size;
    }


    if (type == HTTP_CONTENT_JSON) {
        ret = parse_payload_json(ctx, tag, request->data.data, request->data.len);
    }
    else if (type == HTTP_CONTENT_URLENCODED) {
        ret = parse_payload_urlencoded(ctx, tag, request->data.data, request->data.len);
    }

    if (out_chunked) {
        mk_mem_free(out_chunked);
        request->data.data = original_data;
        request->data.len = original_data_size;
    }

    if (ret != 0) {
        send_response(conn, 400, "error: invalid payload\n");
        return -1;
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
        flb_sds_cat_safe(&tag, uri + 1, len - 1);

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

    if (ret == 0) {
        send_response(conn, ctx->successful_response_code, NULL);
    }
    else {
        send_response(conn, 400, "unable to process records\n");
    }

    return ret;
}


/*
 * Handle an incoming request which has resulted in an http parser error.
 */
int http_prot_handle_error(struct flb_http *ctx, struct http_conn *conn,
                           struct mk_http_session *session,
                           struct mk_http_request *request)
{
    send_response(conn, 400, "error: invalid request\n");
    return -1;
}

/* New gen HTTP server */

static int send_response_ng(struct flb_http_response *response,
                            int http_status,
                            char *message)
{
    struct mk_list            *header_iterator;
    struct flb_slist_entry    *header_value;
    struct flb_slist_entry    *header_name;
    struct flb_config_map_val *header_pair;
    struct flb_http           *context;

    context = (struct flb_http *) response->stream->user_data;

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
        flb_http_response_set_message(response, "Forbidden");
    }

    if (http_status == 200 ||
        http_status == 201 ||
        http_status == 204) {

        flb_config_map_foreach(header_iterator,
                               header_pair,
                               context->success_headers) {
            header_name = mk_list_entry_first(header_pair->val.list,
                                            struct flb_slist_entry,
                                            _head);

            header_value = mk_list_entry_last(header_pair->val.list,
                                            struct flb_slist_entry,
                                            _head);

            flb_http_response_set_header(response,
                                        header_name->str, 0,
                                        header_value->str, 0);
        }
    }

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int process_pack_ng(struct flb_http *ctx, flb_sds_t tag, char *buf, size_t size)
{
    int ret;
    size_t off = 0;
    msgpack_unpacked result;
    struct flb_time tm;
    int i = 0;
    msgpack_object *obj;
    msgpack_object record;
    flb_sds_t tag_from_record = NULL;

    flb_time_get(&tm);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            tag_from_record = NULL;
            obj = &result.data;

            if (ctx->tag_key) {
                tag_from_record = tag_key(ctx, obj);
            }

            if (tag_from_record) {
                ret = process_pack_record(ctx, &tm, tag_from_record, obj);
                flb_sds_destroy(tag_from_record);
            }
            else if (tag) {
                ret = process_pack_record(ctx, &tm, tag, obj);
            }
            else {
                ret = process_pack_record(ctx, &tm, NULL, obj);
            }

            if (ret != 0) {
                goto log_event_error;
            }

            flb_log_event_encoder_reset(&ctx->log_encoder);
        }
        else if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            obj = &result.data;
            for (i = 0; i < obj->via.array.size; i++)
            {
                record = obj->via.array.ptr[i];

                if (tag_from_record) {
                    ret = process_pack_record(ctx, &tm, tag_from_record, &record);
                    flb_sds_destroy(tag_from_record);
                }
                else if (tag) {
                    ret = process_pack_record(ctx, &tm, tag, &record);
                }
                else {
                    ret = process_pack_record(ctx, &tm, NULL, &record);
                }

                if (ret != 0) {
                    goto log_event_error;
                }

                /* TODO : Optimize this
                 *
                 * This is wasteful, considering that we are emitting a series
                 * of records we should start and commit each one and then
                 * emit them all at once after the loop.
                 */

                flb_log_event_encoder_reset(&ctx->log_encoder);
            }

            break;
        }
        else {
            flb_plg_error(ctx->ins, "skip record from invalid type: %i",
                         result.data.type);

            msgpack_unpacked_destroy(&result);

            return -1;
        }
    }

    msgpack_unpacked_destroy(&result);
    return 0;

log_event_error:
    flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
    msgpack_unpacked_destroy(&result);
    return -1;
}

static ssize_t parse_payload_json_ng(flb_sds_t tag,
                                     struct flb_http_request *request)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;
    struct flb_http *ctx;
    char *payload;
    size_t size;

    ctx = (struct flb_http *) request->stream->user_data;
    payload = (char *) request->body;
    size = cfl_sds_len(request->body);

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
    ret = process_pack_ng(ctx, tag, pack, out_size);
    flb_free(pack);

    return ret;
}

static int process_payload_ng(flb_sds_t tag,
                              struct flb_http_request *request,
                              struct flb_http_response *response)
{
    int type = -1;
    cfl_sds_t payload;
    struct flb_http *ctx;

    if (request->content_type == NULL) {
        send_response_ng(response, 400, "error: header 'Content-Type' is not set\n");
        return -1;
    }

    if (strcasecmp(request->content_type, "application/json") == 0) {
        type = HTTP_CONTENT_JSON;
    }

    if (strcasecmp(request->content_type, "application/x-www-form-urlencoded") == 0) {
        type = HTTP_CONTENT_URLENCODED;
    }

    if (type == -1) {
        send_response_ng(response, 400, "error: invalid 'Content-Type'\n");
        return -1;
    }

    if (request->body == NULL ||
        cfl_sds_len(request->body) == 0) {
        send_response_ng(response, 400, "error: no payload found\n");
        return -1;
    }

    if (type == HTTP_CONTENT_JSON) {
        return parse_payload_json_ng(tag, request);
    }
    else if (type == HTTP_CONTENT_URLENCODED) {
        ctx = (struct flb_http *) request->stream->user_data;
        payload = (char *) request->body;
        if (payload) {
            return parse_payload_urlencoded(ctx, tag, payload, cfl_sds_len(payload));
        }
    }

    return 0;
}

int http_prot_handle_ng(struct flb_http_request *request,
                        struct flb_http_response *response)
{
    int                             i;
    int                             ret;
    int                             len;
    flb_sds_t                       tag;
    struct flb_http                *ctx;

    ctx = (struct flb_http *) response->stream->user_data;
    if (request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    /* Compose the query string using the URI */
    len = cfl_sds_len(request->path);

    if (len == 1) {
        tag = NULL; /* use default tag */
    }
    else {
        tag = flb_sds_create(&request->path[1]);

        if (tag == NULL) {
            return -1;
        }

        /* Sanitize, only allow alphanum chars */
        for (i = 0; i < flb_sds_len(tag); i++) {
            if (!isalnum(tag[i]) && tag[i] != '_' && tag[i] != '.') {
                tag[i] = '_';
            }
        }
    }

    /* ToDo: Fix me */
    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {
        flb_sds_destroy(tag);

        return -1;
    }

    if (request->method != HTTP_METHOD_POST) {
        send_response_ng(response, 400, "error: invalid HTTP method\n");
        flb_sds_destroy(tag);

        return -1;
    }

    ret = process_payload_ng(tag, request, response);
    flb_sds_destroy(tag);

    if (ret == 0) {
        send_response_ng(response, ctx->successful_response_code, NULL);
    }
    else {
        send_response_ng(response, 400, "error: unable to process records\n");
    }

    return ret;
}
