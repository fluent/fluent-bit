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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include <monkey/monkey.h>
#include <monkey/mk_core.h>

#include "in_elasticsearch.h"
#include "in_elasticsearch_bulk_conn.h"
#include "in_elasticsearch_bulk_prot.h"

#define HTTP_CONTENT_JSON   0
#define HTTP_CONTENT_NDJSON 1

static int send_dummy_version_response(struct in_elasticsearch_bulk_conn *conn, int http_status, char *message)
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
                       "HTTP/1.1 400 Forbidden\r\n"
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

static inline void map_pack_each(msgpack_packer *packer,
                                 msgpack_object *map)
{
    int i;
    msgpack_object *key;

    for (i = 0; i < map->via.map.size; i++) {
        key = &map->via.map.ptr[i].key;
        msgpack_pack_object(packer, *key);
        msgpack_pack_object(packer, map->via.map.ptr[i].val);
    }
}

static int count_map_elements(struct flb_in_elasticsearch *ctx, char *buf, size_t size, int idx)
{
    msgpack_unpacked result;
    int index = 0;
    int map_num = 0;
    msgpack_object *obj;
    size_t off = 0;

    msgpack_unpacked_init(&result);

    /* Iterate each item to know map number */
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (idx >= index) {
            index++;
            continue;
        }

        if (result.data.type == MSGPACK_OBJECT_MAP) {
            obj = &result.data;
            map_num = obj->via.map.size;
            break;
        }
        else if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            obj = &result.data;
            map_num = obj->via.array.size;
            break;
        }
    }
    msgpack_unpacked_destroy(&result);

    return map_num;
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
    size_t off = 0;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_unpacked result;
    struct flb_time tm;
    msgpack_object *obj;
    flb_sds_t tag_from_record = NULL;
    int map_num  = 0;
    int idx = 0;
    int cursor = 0;
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
                msgpack_sbuffer_init(&mp_sbuf);
                msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

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
                        msgpack_sbuffer_destroy(&mp_sbuf);
                        flb_sds_destroy(write_op);

                        goto proceed;
                    }
                    else {
                        flb_sds_cat(bulk_statuses, "{\"unknown\":{\"status\":400,\"result\":\"bad_request\"}}", 49);
                        error_op = FLB_TRUE;

                        msgpack_sbuffer_destroy(&mp_sbuf);
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
                    msgpack_pack_array(&mp_pck, 2);
                    flb_time_append_to_msgpack(&tm, &mp_pck, 0);

                    /* Prepare map for records */
                    map_num = count_map_elements(ctx, buf, size, cursor);
                    msgpack_pack_map(&mp_pck, map_num + 1);

                    /* Pack meta */
                    msgpack_pack_str(&mp_pck, strlen(ctx->meta_key));
                    msgpack_pack_str_body(&mp_pck, ctx->meta_key, strlen(ctx->meta_key));
                    msgpack_pack_object(&mp_pck, result.data);
                }
            }
            else if (idx % 2 == 1) {
                if (error_op == FLB_FALSE) {
                    /* Pack body */
                    map_pack_each(&mp_pck, &result.data);

                    tag_from_record = NULL;
                    if (ctx->tag_key) {
                        obj = &result.data;
                        tag_from_record = tag_key(ctx, obj);
                    }

                    if (tag_from_record) {
                        flb_input_log_append(ctx->ins, tag_from_record, flb_sds_len(tag_from_record),
                                             mp_sbuf.data, mp_sbuf.size);
                        flb_sds_destroy(tag_from_record);
                    }
                    else if (tag) {
                        flb_input_log_append(ctx->ins, tag, flb_sds_len(tag),
                                             mp_sbuf.data, mp_sbuf.size);
                    }
                    else {
                        /* use default plugin Tag (it internal name, e.g: http.0 */
                        flb_input_log_append(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
                    }
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
                        msgpack_sbuffer_destroy(&mp_sbuf);
                        flb_sds_destroy(write_op);

                        break;
                    }
                }
                msgpack_sbuffer_destroy(&mp_sbuf);
                flb_sds_destroy(write_op);
            }

        proceed:
            idx++;
            cursor++;
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
            msgpack_sbuffer_destroy(&mp_sbuf);
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
    struct mk_http_header *header;

    header = &session->parser.headers[MK_HEADER_CONTENT_TYPE];
    if (header->key.data == NULL) {
        send_response(conn, 400, "error: header 'Content-Type' is not set\n");
        return -1;
    }

    if (header->val.len == 20 &&
        strncasecmp(header->val.data, "application/x-ndjson", 20) == 0) {
        type = HTTP_CONTENT_NDJSON;
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

    if (type == HTTP_CONTENT_NDJSON || type == HTTP_CONTENT_JSON) {
        parse_payload_ndjson(ctx, tag, request->data.data, request->data.len, bulk_statuses);
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
    flb_sds_t bulk_statuses;
    flb_sds_t bulk_response;
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

    if (request->method == MK_METHOD_GET) {
        if (strncmp(uri, "/_nodes/http", 12) == 0) {
            send_dummy_sniffer_response(conn, 200, ctx);
        } else {
            send_dummy_version_response(conn, 200, ES_VERSION_RESPONSE);
        }

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        return 0;
    }

    if (request->method == MK_METHOD_POST) {
        if (strncmp(uri, "/_bulk", 6) == 0) {
            bulk_statuses = flb_sds_create_size(ctx->buffer_max_size);
            if (!bulk_statuses) {
                return -1;
            }

            bulk_response = flb_sds_create_size(ctx->buffer_max_size);
            if (!bulk_response) {
                return -1;
            }
        } else {
            flb_sds_destroy(tag);
            mk_mem_free(uri);

            send_response(conn, 400, "error: invaild HTTP endpoint\n");

            return -1;
        }
    }

    if (request->method != MK_METHOD_POST) {
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
