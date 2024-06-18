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
#include <fluent-bit/flb_gzip.h>

#include <monkey/monkey.h>
#include <monkey/mk_core.h>

#include "in_elasticsearch.h"
#include "in_elasticsearch_bulk_conn.h"
#include "in_elasticsearch_bulk_prot.h"

#define HTTP_CONTENT_JSON   0
#define HTTP_CONTENT_NDJSON 1

static int send_empty_response(struct in_elasticsearch_bulk_conn *conn, int http_status)
{
    size_t    sent;
    flb_sds_t out;

    out = flb_sds_create_size(256);
    if (!out) {
        return -1;
    }

    if (http_status == 200) {
        flb_sds_printf(&out,
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json\r\n\r\n");
    }

    /* We should check this operations result */
    flb_io_net_write(conn->connection,
                     (void *) out,
                     flb_sds_len(out),
                     &sent);

    flb_sds_destroy(out);

    return 0;
}

static int send_json_message_response(struct in_elasticsearch_bulk_conn *conn, int http_status, char *message)
{
    size_t    sent;
    int       len;
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

    if (http_status == 200) {
        flb_sds_printf(&out,
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: %i\r\n\r\n%s",
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

static int send_version_message_response(struct flb_in_elasticsearch *ctx,
                                         struct in_elasticsearch_bulk_conn *conn, int http_status)
{
    size_t    sent;
    int       len;
    flb_sds_t out;
    flb_sds_t resp;

    out = flb_sds_create_size(256);
    if (!out) {
        return -1;
    }
    resp = flb_sds_create_size(384);
    if (!resp) {
        flb_sds_destroy(out);
        return -1;
    }

    flb_sds_printf(&resp,
                   ES_VERSION_RESPONSE_TEMPLATE,
                   ctx->es_version);

    len = flb_sds_len(resp);

    if (http_status == 200) {
        flb_sds_printf(&out,
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: %i\r\n\r\n%s",
                       len, resp);
    }

    /* We should check this operations result */
    flb_io_net_write(conn->connection,
                     (void *) out,
                     flb_sds_len(out),
                     &sent);

    flb_sds_destroy(resp);
    flb_sds_destroy(out);

    return 0;
}

static int send_dummy_sniffer_response(struct in_elasticsearch_bulk_conn *conn, int http_status,
                                       struct flb_in_elasticsearch *ctx)
{
    size_t    sent;
    int       len;
    flb_sds_t out;
    flb_sds_t resp;
    flb_sds_t hostname;

    if (ctx->hostname != NULL) {
        hostname = ctx->hostname;
    }
    else {
        hostname = "localhost";
    }

    out = flb_sds_create_size(384);
    if (!out) {
        return -1;
    }

    resp = flb_sds_create_size(384);
    if (!resp) {
        flb_sds_destroy(out);
        return -1;
    }

    flb_sds_printf(&resp,
                   ES_NODES_TEMPLATE,
                   ctx->cluster_name, ctx->node_name,
                   hostname, ctx->tcp_port, ctx->buffer_max_size);

    len = flb_sds_len(resp) ;

    if (http_status == 200) {
        flb_sds_printf(&out,
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: %i\r\n\r\n%s",
                       len, resp);
    }

    /* We should check this operations result */
    flb_io_net_write(conn->connection,
                     (void *) out,
                     flb_sds_len(out),
                     &sent);

    flb_sds_destroy(resp);
    flb_sds_destroy(out);

    return 0;
}

static int send_response(struct in_elasticsearch_bulk_conn *conn, int http_status, char *message)
{
    size_t    sent;
    int       len;
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

    if (http_status == 200) {
        flb_sds_printf(&out,
                       "HTTP/1.1 200 OK\r\n"
                       "Server: Fluent Bit v%s\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: %i\r\n\r\n%s",
                       FLB_VERSION_STR,
                       len, message);
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
static flb_sds_t tag_key(struct flb_in_elasticsearch *ctx, msgpack_object *map)
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

static int get_write_op(struct flb_in_elasticsearch *ctx, msgpack_object *map, flb_sds_t *out_write_op, size_t *out_key_size)
{
    char *op_str = NULL;
    size_t op_str_size = 0;
    msgpack_object_kv *kv;
    msgpack_object key;
    int check = FLB_FALSE;

    kv = map->via.map.ptr;
    key = kv[0].key;
    if (key.type == MSGPACK_OBJECT_BIN) {
        op_str  = (char *) key.via.bin.ptr;
        op_str_size = key.via.bin.size;
        check = FLB_TRUE;
    }
    if (key.type == MSGPACK_OBJECT_STR) {
        op_str  = (char *) key.via.str.ptr;
        op_str_size = key.via.str.size;
        check = FLB_TRUE;
    }

    if (check == FLB_TRUE) {
        *out_write_op = flb_sds_create_len(op_str, op_str_size);
        *out_key_size = op_str_size;
    }

    return check;
}

static int status_buffer_avail(struct flb_in_elasticsearch *ctx, flb_sds_t bulk_statuses, size_t threshold)
{
    if (flb_sds_avail(bulk_statuses) < threshold) {
        flb_plg_warn(ctx->ins, "left buffer for bulk status(es) is too small");

        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int process_ndpack(struct flb_in_elasticsearch *ctx, flb_sds_t tag, char *buf, size_t size, flb_sds_t bulk_statuses)
{
    int ret;
    size_t off = 0;
    size_t map_copy_index;
    msgpack_object_kv *map_copy_entry;
    msgpack_unpacked result;
    struct flb_time tm;
    msgpack_object *obj;
    flb_sds_t tag_from_record = NULL;
    int idx = 0;
    flb_sds_t write_op;
    size_t op_str_size = 0;
    int op_ret = FLB_FALSE;
    int error_op = FLB_FALSE;

    flb_time_get(&tm);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            if (idx > 0 && idx % 2 == 0) {
                flb_sds_cat(bulk_statuses, ",", 1);
            }
            if (status_buffer_avail(ctx, bulk_statuses, 50) == FLB_FALSE) {
                break;
            }
            if (idx % 2 == 0) {
                op_ret = get_write_op(ctx, &result.data, &write_op, &op_str_size);

                if (op_ret) {
                    if (flb_sds_cmp(write_op, "index", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"index\":", 9);
                        error_op = FLB_FALSE;
                    }
                    else if (flb_sds_cmp(write_op, "create", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"create\":", 10);
                        error_op = FLB_FALSE;
                    }
                    else if (flb_sds_cmp(write_op, "update", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"update\":", 10);
                        error_op = FLB_TRUE;
                    }
                    else if (flb_sds_cmp(write_op, "delete", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"delete\":{\"status\":404,\"result\":\"not_found\"}}", 46);
                        error_op = FLB_TRUE;
                        idx += 1; /* Prepare to adjust to multiple of two
                                   * in the end of the loop.
                                   * Due to delete actions include only one line. */
                        flb_sds_destroy(write_op);

                        goto proceed;
                    }
                    else {
                        flb_sds_cat(bulk_statuses, "{\"unknown\":{\"status\":400,\"result\":\"bad_request\"}}", 49);
                        error_op = FLB_TRUE;

                        flb_sds_destroy(write_op);

                        break;
                    }
                } else {
                    flb_sds_destroy(write_op);
                    flb_plg_error(ctx->ins, "meta information line is missing");
                    error_op = FLB_TRUE;

                    break;
                }

                if (error_op == FLB_FALSE) {
                    flb_log_event_encoder_reset(&ctx->log_encoder);

                    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_sds_destroy(write_op);
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    ret = flb_log_event_encoder_set_timestamp(
                            &ctx->log_encoder,
                            &tm);

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_sds_destroy(write_op);
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                        ret = flb_log_event_encoder_append_body_values(
                                &ctx->log_encoder,
                                FLB_LOG_EVENT_CSTRING_VALUE((char *) ctx->meta_key),
                                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&result.data));
                    }

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_sds_destroy(write_op);
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }
                }
            }
            else if (idx % 2 == 1) {
                if (error_op == FLB_FALSE) {
                    /* Pack body */

                    for (map_copy_index = 0 ;
                         map_copy_index < result.data.via.map.size &&
                         ret == FLB_EVENT_ENCODER_SUCCESS ;
                         map_copy_index++) {
                        map_copy_entry = &result.data.via.map.ptr[map_copy_index];

                        ret = flb_log_event_encoder_append_body_values(
                                &ctx->log_encoder,
                                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&map_copy_entry->key),
                                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&map_copy_entry->val));
                    }

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    tag_from_record = NULL;

                    if (ctx->tag_key) {
                        obj = &result.data;
                        tag_from_record = tag_key(ctx, obj);
                    }

                    if (tag_from_record) {
                        flb_input_log_append(ctx->ins,
                                             tag_from_record,
                                             flb_sds_len(tag_from_record),
                                             ctx->log_encoder.output_buffer,
                                             ctx->log_encoder.output_length);

                        flb_sds_destroy(tag_from_record);
                    }
                    else if (tag) {
                        flb_input_log_append(ctx->ins,
                                             tag,
                                             flb_sds_len(tag),
                                             ctx->log_encoder.output_buffer,
                                             ctx->log_encoder.output_length);
                    }
                    else {
                        /* use default plugin Tag (it internal name, e.g: http.0 */
                        flb_input_log_append(ctx->ins, NULL, 0,
                                             ctx->log_encoder.output_buffer,
                                             ctx->log_encoder.output_length);
                    }

                    flb_log_event_encoder_reset(&ctx->log_encoder);
                }
                if (op_ret) {
                    if (flb_sds_cmp(write_op, "index", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"status\":201,\"result\":\"created\"}}", 34);
                    }
                    else if (flb_sds_cmp(write_op, "create", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"status\":201,\"result\":\"created\"}}", 34);
                    }
                    else if (flb_sds_cmp(write_op, "update", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"status\":403,\"result\":\"forbidden\"}}", 36);
                    }
                    if (status_buffer_avail(ctx, bulk_statuses, 50) == FLB_FALSE) {
                        flb_sds_destroy(write_op);

                        break;
                    }
                }
                flb_sds_destroy(write_op);
            }

        proceed:
            idx++;
        }
        else {
            flb_plg_error(ctx->ins, "skip record from invalid type: %i",
                         result.data.type);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }

    if (idx % 2 != 0) {
        flb_plg_warn(ctx->ins, "decode payload of Bulk API is failed");
        msgpack_unpacked_destroy(&result);
        if (error_op == FLB_FALSE) {
            /* On lacking of body case in non-error case, there is no
             * releasing memory code paths. We should proceed to do
             * it here. */
            flb_sds_destroy(write_op);
        }

        return -1;
    }

    msgpack_unpacked_destroy(&result);

    return 0;
}

static ssize_t parse_payload_ndjson(struct flb_in_elasticsearch *ctx, flb_sds_t tag,
                                    char *payload, size_t size, flb_sds_t bulk_statuses)
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
    process_ndpack(ctx, tag, pack, out_size, bulk_statuses);
    flb_free(pack);

    return 0;
}

static int process_payload(struct flb_in_elasticsearch *ctx, struct in_elasticsearch_bulk_conn *conn,
                           flb_sds_t tag,
                           struct mk_http_session *session,
                           struct mk_http_request *request,
                           flb_sds_t bulk_statuses)
{
    int type = -1;
    int i = 0;
    int ret = 0;
    struct mk_http_header *header;
    int extra_size = -1;
    struct mk_http_header *headers_extra;
    int gzip_compressed = FLB_FALSE;
    void *gz_data = NULL;
    size_t gz_size = -1;

    header = &session->parser.headers[MK_HEADER_CONTENT_TYPE];
    if (header->key.data == NULL) {
        send_response(conn, 400, "error: header 'Content-Type' is not set\n");
        return -1;
    }

    if (header->val.len >= 20 &&
        strncasecmp(header->val.data, "application/x-ndjson", 20) == 0) {
        type = HTTP_CONTENT_NDJSON;
    }

    if (header->val.len >= 16 &&
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

    extra_size = session->parser.headers_extra_count;
    if (extra_size > 0) {
        for (i = 0; i < extra_size; i++) {
            headers_extra = &session->parser.headers_extra[i];
            if (headers_extra->key.len == 16 &&
                strncasecmp(headers_extra->key.data, "Content-Encoding", 16) == 0) {
                if (headers_extra->val.len == 4 &&
                    strncasecmp(headers_extra->val.data, "gzip", 4) == 0) {
                    flb_debug("[elasticsearch_bulk_prot] body is gzipped");
                    gzip_compressed = FLB_TRUE;
                }
            }
        }
    }

    if (type == HTTP_CONTENT_NDJSON || type == HTTP_CONTENT_JSON) {
        if (gzip_compressed == FLB_TRUE) {
            ret = flb_gzip_uncompress((void *) request->data.data, request->data.len,
                                      &gz_data, &gz_size);
            if (ret == -1) {
                flb_error("[elasticsearch_bulk_prot] gzip uncompress is failed");
                return -1;
            }
            parse_payload_ndjson(ctx, tag, gz_data, gz_size, bulk_statuses);
            flb_free(gz_data);
        }
        else {
            parse_payload_ndjson(ctx, tag, request->data.data, request->data.len, bulk_statuses);
        }
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
int in_elasticsearch_bulk_prot_handle(struct flb_in_elasticsearch *ctx,
                                      struct in_elasticsearch_bulk_conn *conn,
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
    flb_sds_t bulk_statuses = NULL;
    flb_sds_t bulk_response = NULL;
    char *error_str = NULL;

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

    /* Refer the tag at first*/
    if (ctx->ins->tag && !ctx->ins->tag_default) {
        tag = flb_sds_create(ctx->ins->tag);
        if (tag == NULL) {
            return -1;
        }
    }
    else {
        /* Compose the query string using the URI */
        len = strlen(uri);

        if (len == 1) {
            tag = NULL; /* use default tag */
        }
        else {
            /* New tag skipping the URI '/' */
            tag = flb_sds_create_len(&uri[1], len - 1);
            if (!tag) {
                mk_mem_free(uri);
                return -1;
            }

            /* Sanitize, only allow alphanum chars */
            for (i = 0; i < flb_sds_len(tag); i++) {
                if (!isalnum(tag[i]) && tag[i] != '_' && tag[i] != '.') {
                    tag[i] = '_';
                }
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

    if (request->method == MK_METHOD_HEAD) {
        send_empty_response(conn, 200);

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        return 0;
    }

    if (request->method == MK_METHOD_PUT) {
        send_json_message_response(conn, 200, "{}");

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        return 0;
    }

    if (request->method == MK_METHOD_GET) {
        if (strncmp(uri, "/_nodes/http", 12) == 0) {
            send_dummy_sniffer_response(conn, 200, ctx);
        }
        else if (strlen(uri) == 1 && strncmp(uri, "/", 1) == 0) {
            send_version_message_response(ctx, conn, 200);
        }
        else {
            send_json_message_response(conn, 200, "{}");
        }

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        return 0;
    }

    if (request->method == MK_METHOD_POST) {
        if (strncmp(uri, "/_bulk", 6) == 0) {
            bulk_statuses = flb_sds_create_size(ctx->buffer_max_size);
            if (!bulk_statuses) {
                flb_sds_destroy(tag);
                mk_mem_free(uri);
                return -1;
            }

            bulk_response = flb_sds_create_size(ctx->buffer_max_size);
            if (!bulk_response) {
                flb_sds_destroy(bulk_statuses);
                flb_sds_destroy(tag);
                mk_mem_free(uri);
                return -1;
            }
        } else {
            flb_sds_destroy(tag);
            mk_mem_free(uri);

            send_response(conn, 400, "error: invalid HTTP endpoint\n");

            return -1;
        }
    }

    if (request->method != MK_METHOD_POST &&
        request->method != MK_METHOD_GET &&
        request->method != MK_METHOD_HEAD &&
        request->method != MK_METHOD_PUT) {

        if (bulk_statuses) {
            flb_sds_destroy(bulk_statuses);
        }
        if (bulk_response) {
            flb_sds_destroy(bulk_response);
        }

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        send_response(conn, 400, "error: invalid HTTP method\n");
        return -1;
    }

    ret = process_payload(ctx, conn, tag, session, request, bulk_statuses);
    flb_sds_destroy(tag);

    len = flb_sds_len(bulk_statuses);
    if (flb_sds_alloc(bulk_response) < len + 27) {
        bulk_response = flb_sds_increase(bulk_response, len + 27 - flb_sds_alloc(bulk_response));
    }
    error_str = strstr(bulk_statuses, "\"status\":40");
    if (error_str){
        flb_sds_cat(bulk_response, "{\"errors\":true,\"items\":[", 24);
    }
    else {
        flb_sds_cat(bulk_response, "{\"errors\":false,\"items\":[", 25);
    }
    flb_sds_cat(bulk_response, bulk_statuses, flb_sds_len(bulk_statuses));
    flb_sds_cat(bulk_response, "]}", 2);
    send_response(conn, 200, bulk_response);

    mk_mem_free(uri);
    flb_sds_destroy(bulk_statuses);
    flb_sds_destroy(bulk_response);

    return ret;
}

/*
 * Handle an incoming request which has resulted in an http parser error.
 */
int in_elasticsearch_bulk_prot_handle_error(struct flb_in_elasticsearch *ctx,
                                            struct in_elasticsearch_bulk_conn *conn,
                                            struct mk_http_session *session,
                                            struct mk_http_request *request)
{
    send_response(conn, 400, "error: invalid request\n");
    return -1;
}




/* New gen HTTP server */
static int send_response_ng(struct flb_http_response *response, 
                            int http_status, 
                            char *content_type,
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
        flb_http_response_set_message(response, "Forbidden");
    }

    if (content_type != NULL) {
        flb_http_response_set_header(response, 
                                     "content-type", 0,
                                     content_type, 0);
    }

    if (message != NULL) {
        flb_http_response_set_body(response, 
                                   (unsigned char *) message, 
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int send_json_response_ng(struct flb_http_response *response, 
                                 int http_status,
                                 char *message)
{
    return send_response_ng(response, http_status, "application/json", message); 
}

static int send_version_message_response_ng(struct flb_http_response *response, 
                                            struct flb_in_elasticsearch *ctx,
                                            int http_status)
{
    flb_sds_t message;

    if (http_status != 200) {
        return 0;
    }

    message = flb_sds_create_size(384);

    if (message == NULL) {
        return -1;
    }

    flb_sds_printf(&message,
                   ES_VERSION_RESPONSE_TEMPLATE,
                   ctx->es_version);

    send_json_response_ng(response, http_status, message); 

    cfl_sds_destroy(message);

    return 0;
}

static int send_dummy_sniffer_response_ng(struct flb_http_response *response, 
                                          struct flb_in_elasticsearch *ctx,
                                          int http_status)
{
    flb_sds_t hostname;
    flb_sds_t resp;

    if (http_status != 200) {
        return 0;
    }

    if (ctx->hostname != NULL) {
        hostname = ctx->hostname;
    }
    else {
        hostname = "localhost";
    }

    resp = flb_sds_create_size(384);
    if (!resp) {
        return -1;
    }

    flb_sds_printf(&resp,
                   ES_NODES_TEMPLATE,
                   ctx->cluster_name, ctx->node_name,
                   hostname, ctx->tcp_port, ctx->buffer_max_size);

    send_json_response_ng(response, http_status, resp); 

    flb_sds_destroy(resp);

    return 0;
}

static int process_payload_ng(struct flb_http_request *request,
                              struct flb_http_response *response,
                              struct flb_in_elasticsearch *context,
                              flb_sds_t tag,
                              flb_sds_t bulk_statuses)
{
    if (request->content_type == NULL) {
        send_response_ng(response, 400, NULL, "error: header 'Content-Type' is not set\n");

        return -1;
    }

    if (strncasecmp(request->content_type, "application/x-ndjson", 20) != 0 &&
        strncasecmp(request->content_type, "application/json", 16) != 0) {
        send_response_ng(response, 400, NULL, "error: invalid 'Content-Type'\n");

        return -1;
    }

    if (request->body == NULL || cfl_sds_len(request->body) == 0) {
        send_response_ng(response, 400, NULL, "error: no payload found\n");
        return -1;
    }

    parse_payload_ndjson(context, tag, request->body, cfl_sds_len(request->body), bulk_statuses);

    return 0;
}

int in_elasticsearch_bulk_prot_handle_ng(struct flb_http_request *request,
                                         struct flb_http_response *response)
{
    flb_sds_t                    bulk_statuses;
    flb_sds_t                    bulk_response;
    const char                  *error_str;
    struct flb_in_elasticsearch *context;
    flb_sds_t                    tag;
    size_t                       len;

    bulk_statuses = NULL;
    bulk_response = NULL;

    context = (struct flb_in_elasticsearch *) response->stream->user_data;

    if (request->path[0] != '/') {
        send_response_ng(response, 400, NULL, "error: invalid request\n");
        return -1;
    }

    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_HTTP1 && 
        request->host == NULL) {

        return -1;
    }

    if (request->method == HTTP_METHOD_HEAD) {
        send_response_ng(response, 200, NULL, NULL);

        return -1;
    }
    else if (request->method == HTTP_METHOD_PUT) {
        send_json_response_ng(response, 200, "{}");

        return -1;
    }
    else if (request->method == HTTP_METHOD_GET) {
        if (strncmp(request->path, "/_nodes/http", 12) == 0) {
            send_dummy_sniffer_response_ng(response, context, 200);
        }
        else if (strcmp(request->path, "/") == 0) {
            send_version_message_response_ng(response, context, 200);
        }
        else {
            send_json_response_ng(response, 200, "{}");
        }

        return 0;
    }
    else if (request->method == HTTP_METHOD_POST) {
        if (strcmp(request->path, "/_bulk") == 0) {
            bulk_statuses = flb_sds_create_size(context->buffer_max_size);
            
            if (bulk_statuses == NULL) {
                return -1;
            }

            bulk_response = flb_sds_create_size(context->buffer_max_size);

            if (bulk_response == NULL) {
                flb_sds_destroy(bulk_statuses);
                return -1;
            }

            tag = flb_sds_create(context->ins->tag);

            if (tag == NULL) {
                flb_sds_destroy(bulk_statuses);
                flb_sds_destroy(bulk_response);
                return -1;
            }

            process_payload_ng(request, response, context, tag, bulk_statuses);

            flb_sds_destroy(tag);

            len = flb_sds_len(bulk_statuses);

            if (flb_sds_alloc(bulk_response) < len + 27) {
                bulk_response = flb_sds_increase(bulk_response, len + 27 - flb_sds_alloc(bulk_response));
            }

            error_str = strstr(bulk_statuses, "\"status\":40");

            if (error_str){
                flb_sds_cat(bulk_response, "{\"errors\":true,\"items\":[", 24);
            }
            else {
                flb_sds_cat(bulk_response, "{\"errors\":false,\"items\":[", 25);
            }

            flb_sds_cat(bulk_response, bulk_statuses, flb_sds_len(bulk_statuses));
            flb_sds_cat(bulk_response, "]}", 2);

            send_json_response_ng(response, 200, bulk_response);

            flb_sds_destroy(bulk_statuses);
            flb_sds_destroy(bulk_response);
                        
        } else {
            send_response_ng(response, 400, NULL, "error: invalid HTTP endpoint\n");

            return -1;
        }
    }
    else {
        send_response_ng(response, 400, NULL, "error: invalid HTTP method\n");

        return -1;
    }
    
    return 0;
}