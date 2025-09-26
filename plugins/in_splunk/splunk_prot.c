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

#include "splunk.h"
#include "splunk_conn.h"
#include "splunk_prot.h"

#define HTTP_CONTENT_JSON  0
#define HTTP_CONTENT_TEXT  1
#define HTTP_CONTENT_UNKNOWN 2

static int send_response(struct splunk_conn *conn, int http_status, char *message)
{
    struct flb_splunk *context;
    size_t           sent;
    int              len;
    flb_sds_t        out;

    context = (struct flb_splunk *) conn->ctx;

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
    else if (http_status == 401) {
        flb_sds_printf(&out,
                       "HTTP/1.1 401 Unauthorized\r\n"
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

static int send_json_message_response(struct splunk_conn *conn, int http_status, char *message)
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
    else if (http_status == 400) {
        flb_sds_printf(&out,
                       "HTTP/1.1 400 Bad Request\r\n"
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

/* implements functionality to get tag from key in record */
static flb_sds_t tag_key(struct flb_splunk *ctx, msgpack_object *map)
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

/*
 * Process a raw text payload for Splunk HEC requests, uses the delimited character to split records,
 * return the number of processed bytes
 */
static int process_raw_payload_pack(struct flb_splunk *ctx, flb_sds_t tag, char *buf, size_t size)
{
    int ret = FLB_EVENT_ENCODER_SUCCESS;

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(&ctx->log_encoder);
    }

    if (ctx->store_token_in_metadata == FLB_TRUE) {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("log"),
                    FLB_LOG_EVENT_STRING_VALUE(buf, size));
        }
    }

    if (ctx->store_token_in_metadata == FLB_TRUE) {
        if (ctx->ingested_auth_header != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_metadata_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("hec_token"),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->ingested_auth_header,
                                               ctx->ingested_auth_header_len));
            }
        }
    }
    else {
        if (ctx->ingested_auth_header != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(ctx->store_token_key),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->ingested_auth_header,
                                               ctx->ingested_auth_header_len),
                    FLB_LOG_EVENT_CSTRING_VALUE("log"),
                    FLB_LOG_EVENT_STRING_VALUE(buf, size));

            }
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(&ctx->log_encoder);
        return -1;
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (tag) {
            flb_input_log_append(ctx->ins, tag, flb_sds_len(tag),
                                 ctx->log_encoder.output_buffer,
                                 ctx->log_encoder.output_length);
        }
        else {
            /* use default plugin Tag (it internal name, e.g: http.0 */
            flb_input_log_append(ctx->ins, NULL, 0,
                                 ctx->log_encoder.output_buffer,
                                 ctx->log_encoder.output_length);
        }
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", ret);
    }

    return 0;
}

static void process_flb_log_append(struct flb_splunk *ctx, msgpack_object *record,
                                   flb_sds_t tag, flb_sds_t tag_from_record,
                                   struct flb_time tm) {
    int ret;
    int i;
    msgpack_object_kv *kv;

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(
                &ctx->log_encoder,
                &tm);
    }

    if (ctx->store_token_in_metadata == FLB_TRUE) {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_body_from_msgpack_object(
                    &ctx->log_encoder,
                    record);
        }

        if (ctx->ingested_auth_header != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_metadata_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("hec_token"),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->ingested_auth_header,
                                               ctx->ingested_auth_header_len));
            }
        }
    }
    else {
        if (ctx->ingested_auth_header != NULL) {
            /* iterate through the old record map to create the appendable new buffer */
            kv = record->via.map.ptr;
            for(i = 0; i < record->via.map.size && ret == FLB_EVENT_ENCODER_SUCCESS; i++) {
                ret = flb_log_event_encoder_append_body_values(
                        &ctx->log_encoder,
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].key),
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].val));
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_values(
                    &ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(ctx->store_token_key),
                    FLB_LOG_EVENT_STRING_VALUE(ctx->ingested_auth_header,
                                               ctx->ingested_auth_header_len));
            }
        }
        else {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_body_from_msgpack_object(
                        &ctx->log_encoder,
                        record);
            }
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (tag_from_record) {
            flb_input_log_append(ctx->ins,
                                 tag_from_record,
                                 flb_sds_len(tag_from_record),
                                 ctx->log_encoder.output_buffer,
                                 ctx->log_encoder.output_length);
        }
        else if (tag) {
            flb_input_log_append(ctx->ins, tag, flb_sds_len(tag),
                                 ctx->log_encoder.output_buffer,
                                 ctx->log_encoder.output_length);
        }
        else {
            /* use default plugin Tag (it internal name, e.g: http.0 */
            flb_input_log_append(ctx->ins, NULL, 0,
                                 ctx->log_encoder.output_buffer,
                                 ctx->log_encoder.output_length);
        }
    }
    else {
        flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
    }

    if (tag_from_record) {
        flb_sds_destroy(tag_from_record);
    }
}

static int process_json_payload_pack(struct flb_splunk *ctx, flb_sds_t tag, char *buf, size_t size)
{
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
            if (ctx->tag_key) {
                tag_from_record = tag_key(ctx, &result.data);
            }

            process_flb_log_append(ctx, &result.data, tag, tag_from_record, tm);

            flb_log_event_encoder_reset(&ctx->log_encoder);
        }
        else if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            obj = &result.data;
            for (i = 0; i < obj->via.array.size; i++)
            {
                record = obj->via.array.ptr[i];

                tag_from_record = NULL;
                if (ctx->tag_key) {
                    tag_from_record = tag_key(ctx, &record);
                }

                process_flb_log_append(ctx, &record, tag, tag_from_record, tm);

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
}

static ssize_t parse_hec_payload_json(struct flb_splunk *ctx, flb_sds_t tag,
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
    process_json_payload_pack(ctx, tag, pack, out_size);
    flb_free(pack);

    return 0;
}

static int validate_auth_header(struct flb_splunk *ctx, struct mk_http_request *request)
{
    int ret = 0;
    struct mk_list *head;
    struct mk_http_header *auth_header = NULL;
    struct flb_splunk_tokens *splunk_token;
    flb_sds_t authorization = NULL;

    if (mk_list_size(&ctx->auth_tokens) == 0) {
        return SPLUNK_AUTH_UNAUTH;
    }

    auth_header = mk_http_header_get(MK_HEADER_AUTHORIZATION, request, NULL, 0);
    if (auth_header == NULL) {
        return SPLUNK_AUTH_MISSING_CRED;
    }

    authorization = flb_sds_create_len(auth_header->val.data, auth_header->val.len);
    if (authorization == NULL) {
        return SPLUNK_AUTH_MISSING_CRED;
    }

    if (authorization != NULL && auth_header->val.len > 0) {
        mk_list_foreach(head, &ctx->auth_tokens) {
            splunk_token = mk_list_entry(head, struct flb_splunk_tokens, _head);
            if (flb_sds_len(authorization) != splunk_token->length) {
                ret = SPLUNK_AUTH_UNAUTHORIZED;
                continue;
            }

            if (strncasecmp(splunk_token->header,
                        authorization,
                        splunk_token->length) == 0) {
                flb_sds_destroy(authorization);

                return SPLUNK_AUTH_SUCCESS;
            }
        }

        ret = SPLUNK_AUTH_UNAUTHORIZED;
        flb_sds_destroy(authorization);
        return ret;
    }
    else {
        flb_sds_destroy(authorization);
        return SPLUNK_AUTH_MISSING_CRED;
    }

    return SPLUNK_AUTH_SUCCESS;
}

static int handle_hec_payload(struct flb_splunk *ctx, int content_type,
                              flb_sds_t tag, char *buf, size_t size)
{
    int ret = -1;

    if (content_type == HTTP_CONTENT_JSON) {
        ret = parse_hec_payload_json(ctx, tag, buf, size);
    }
    else if (content_type == HTTP_CONTENT_TEXT) {
        ret = process_raw_payload_pack(ctx, tag, buf, size);
    }
    else if (content_type == HTTP_CONTENT_UNKNOWN) {
        if (buf[0] == '{') {
            ret = parse_hec_payload_json(ctx, tag, buf, size);
        }
        else {
            ret = process_raw_payload_pack(ctx, tag, buf, size);
        }
    }

    return ret;
}

static int process_hec_payload(struct flb_splunk *ctx, struct splunk_conn *conn,
                               flb_sds_t tag,
                               struct mk_http_session *session,
                               struct mk_http_request *request)
{
    int i = 0;
    int ret = 0;
    int type = -1;
    struct mk_http_header *header;
    struct mk_http_header *header_auth;
    int extra_size = -1;
    struct mk_http_header *headers_extra;
    int gzip_compressed = FLB_FALSE;
    void *gz_data = NULL;
    size_t gz_size = -1;

    header = &session->parser.headers[MK_HEADER_CONTENT_TYPE];
    if (header->key.data == NULL) {
        flb_plg_debug(ctx->ins, "header 'Content-Type' is not set");
    }

    if (header->val.len == 16 &&
        strncasecmp(header->val.data, "application/json", 16) == 0) {
        type = HTTP_CONTENT_JSON;
    }
    else if (header->val.len == 10 &&
        strncasecmp(header->val.data, "text/plain", 10) == 0) {
        type = HTTP_CONTENT_TEXT;
    }
    else {
        /* Not necessary to specify content-type for Splunk HEC. */
        flb_plg_debug(ctx->ins, "Mark as unknown type for ingested payloads");
        type = HTTP_CONTENT_UNKNOWN;
    }

    if (request->data.len <= 0 && !mk_http_parser_is_content_chunked(&session->parser)) {
        send_json_message_response(conn, 400, "{\"text\":\"No data\",\"code\":5}");
        return -2;
    }

    header_auth = &session->parser.headers[MK_HEADER_AUTHORIZATION];
    if (header_auth->key.data != NULL) {
        if (strncasecmp(header_auth->val.data, "Splunk ", 7) == 0) {
            ctx->ingested_auth_header = header_auth->val.data;
            ctx->ingested_auth_header_len = header_auth->val.len;
        }
    }

    extra_size = session->parser.headers_extra_count;
    if (extra_size > 0) {
        for (i = 0; i < extra_size; i++) {
            headers_extra = &session->parser.headers_extra[i];
            if (headers_extra->key.len == 16 &&
                strncasecmp(headers_extra->key.data, "Content-Encoding", 16) == 0) {
                if (headers_extra->val.len == 4 &&
                    strncasecmp(headers_extra->val.data, "gzip", 4) == 0) {
                    flb_plg_debug(ctx->ins, "body is gzipped");
                    gzip_compressed = FLB_TRUE;
                }
            }
        }
    }

    if (gzip_compressed == FLB_TRUE) {
        ret = flb_gzip_uncompress((void *) request->data.data, request->data.len,
                                  &gz_data, &gz_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "gzip uncompress is failed");
            return -1;
        }

        ret = handle_hec_payload(ctx, type, tag, gz_data, gz_size);
        flb_free(gz_data);
    }
    else {
        ret = handle_hec_payload(ctx, type, tag, request->data.data, request->data.len);
    }

    return 0;
}

static int process_hec_raw_payload(struct flb_splunk *ctx, struct splunk_conn *conn,
                                   flb_sds_t tag,
                                   struct mk_http_session *session,
                                   struct mk_http_request *request)
{
    int ret = -1;
    struct mk_http_header *header;
    struct mk_http_header *header_auth;

    header = &session->parser.headers[MK_HEADER_CONTENT_TYPE];
    if (header->key.data == NULL) {
        send_response(conn, 400, "error: header 'Content-Type' is not set\n");
        return -2;
    }
    else if (header->val.len != 10 ||
             strncasecmp(header->val.data, "text/plain", 10) != 0) {
        /* Not necessary to specify content-type for Splunk HEC. */
        flb_plg_debug(ctx->ins, "Mark as unknown type for ingested payloads");
    }

    if (request->data.len <= 0 && !mk_http_parser_is_content_chunked(&session->parser)) {
        send_json_message_response(conn, 400, "{\"text\":\"No data\",\"code\":5}");
        return -2;
    }

    header_auth = &session->parser.headers[MK_HEADER_AUTHORIZATION];
    if (header_auth->key.data != NULL) {
        if (strncasecmp(header_auth->val.data, "Splunk ", 7) == 0) {
            ctx->ingested_auth_header = header_auth->val.data;
            ctx->ingested_auth_header_len = header_auth->val.len;
        }
    }

    /* Always handle as raw type of payloads here */
    ret = process_raw_payload_pack(ctx, tag, request->data.data, request->data.len);

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

/*
 * Handle an incoming request. It perform extra checks over the request, if
 * everything is OK, it enqueue the incoming payload.
 */
int splunk_prot_handle(struct flb_splunk *ctx, struct splunk_conn *conn,
                       struct mk_http_session *session,
                       struct mk_http_request *request)
{
    int i;
    int ret;
    int len;
    char *uri;
    char *qs;
    char *original_data = NULL;
    size_t original_data_size = 0;
    char *out_chunked = NULL;
    size_t out_chunked_size = 0;
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

    /* Refer the tag at first*/
    if (ctx->ins->tag && !ctx->ins->tag_default) {
        tag = flb_sds_create(ctx->ins->tag);
        if (tag == NULL) {
            mk_mem_free(uri);
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
    if (request->host.data == NULL && request->protocol == MK_HTTP_PROTOCOL_11) {
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

    if (request->method == MK_METHOD_GET) {
        /* Handle health monitoring of splunk hec endpoint for load balancers */
        if (strcasecmp(uri, "/services/collector/health") == 0) {
            send_json_message_response(conn, 200, "{\"text\":\"Success\",\"code\":200}");
        }
        else {
            send_response(conn, 400, "error: invalid HTTP endpoint\n");
        }

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        return 0;
    }

    /* Under services/collector endpoints are required for
     * authentication if provided splunk_token */
    ret = validate_auth_header(ctx, request);
    if (ret < 0){
        send_response(conn, 401, "error: unauthorized\n");
        if (ret == SPLUNK_AUTH_MISSING_CRED) {
            flb_plg_warn(ctx->ins, "missing credentials in request headers");
        }
        else if (ret == SPLUNK_AUTH_UNAUTHORIZED) {
            flb_plg_warn(ctx->ins, "wrong credentials in request headers");
        }

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        return -1;
    }

    /* If the request contains chunked transfer encoded data, decode it */\
    if (mk_http_parser_is_content_chunked(&session->parser)) {
        ret = mk_http_parser_chunked_decode(&session->parser,
                                            conn->buf_data,
                                            conn->buf_len,
                                            &out_chunked,
                                            &out_chunked_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "failed to decode chunked data");
            send_response(conn, 400, "error: invalid chunked data\n");

            flb_sds_destroy(tag);
            mk_mem_free(uri);

            return -1;
        }

        /* Update the request data */
        original_data = request->data.data;
        original_data_size = request->data.len;

        /* assign the chunked one */
        request->data.data = out_chunked;
        request->data.len = out_chunked_size;
    }

    /* Handle every ingested payload cleanly */
    flb_log_event_encoder_reset(&ctx->log_encoder);

    if (request->method == MK_METHOD_POST) {
        if (strcasecmp(uri, "/services/collector/raw/1.0") == 0 ||
            strcasecmp(uri, "/services/collector/raw") == 0) {
            ret = process_hec_raw_payload(ctx, conn, tag, session, request);

            if (ret == -2) {
                /* Response already sent, skip further response */
                flb_sds_destroy(tag);
                mk_mem_free(uri);
                if (out_chunked) {
                    mk_mem_free(out_chunked);
                }
                request->data.data = original_data;
                request->data.len = original_data_size;
                return -1;
            }

            if (ret < 0) {
                send_json_message_response(conn, 400, "{\"text\":\"Invalid data format\",\"code\":6}");
            }
            else {
                send_json_message_response(conn, 200, "{\"text\":\"Success\",\"code\":0}");
            }
        }
        else if (strcasecmp(uri, "/services/collector/event/1.0") == 0 ||
                 strcasecmp(uri, "/services/collector/event") == 0 ||
                 strcasecmp(uri, "/services/collector") == 0) {

            ret = process_hec_payload(ctx, conn, tag, session, request);
            if (ret == -2) {
                flb_sds_destroy(tag);
                mk_mem_free(uri);

                if (out_chunked) {
                    mk_mem_free(out_chunked);
                }
                request->data.data = original_data;
                request->data.len = original_data_size;

                return -1;
            }

            if (ret < 0) {
                send_json_message_response(conn, 400, "{\"text\":\"Invalid data format\",\"code\":6}");
            }
            else {
                send_json_message_response(conn, 200, "{\"text\":\"Success\",\"code\":0}");
            }
        }
        else {
            send_response(conn, 400, "error: invalid HTTP endpoint\n");

            flb_sds_destroy(tag);
            mk_mem_free(uri);

            if (out_chunked) {
                mk_mem_free(out_chunked);
            }
            request->data.data = original_data;
            request->data.len = original_data_size;

            return -1;
        }
    }
    else {
        /* HEAD, PUT, PATCH, and DELETE methods are prohibited to use.*/

        flb_sds_destroy(tag);
        mk_mem_free(uri);

        if (out_chunked) {
            mk_mem_free(out_chunked);
        }
        request->data.data = original_data;
        request->data.len = original_data_size;

        send_response(conn, 400, "error: invalid HTTP method\n");
        return -1;
    }

    flb_sds_destroy(tag);
    mk_mem_free(uri);

    if (out_chunked) {
        mk_mem_free(out_chunked);
    }
    request->data.data = original_data;
    request->data.len = original_data_size;

    return ret;
}

/*
 * Handle an incoming request which has resulted in an http parser error.
 */
int splunk_prot_handle_error(struct flb_splunk *ctx, struct splunk_conn *conn,
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

static int send_json_message_response_ng(struct flb_http_response *response,
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

    flb_http_response_set_header(response,
                                "content-type", 0,
                                "application/json", 0);

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int validate_auth_header_ng(struct flb_splunk *ctx, struct flb_http_request *request)
{
    struct mk_list *tmp;
    struct mk_list *head;
    char *auth_header;
    struct flb_splunk_tokens *splunk_token;

    if (mk_list_size(&ctx->auth_tokens) == 0) {
        return SPLUNK_AUTH_UNAUTH;
    }

    auth_header = flb_http_request_get_header(request, "authorization");

    if (auth_header == NULL) {
        return SPLUNK_AUTH_MISSING_CRED;
    }

    if (auth_header != NULL && strlen(auth_header) > 0) {
        mk_list_foreach_safe(head, tmp, &ctx->auth_tokens) {
            splunk_token = mk_list_entry(head, struct flb_splunk_tokens, _head);
            if (strlen(auth_header) != splunk_token->length) {
                continue;
            }

            if (strncasecmp(splunk_token->header,
                        auth_header,
                        splunk_token->length) == 0) {
                return SPLUNK_AUTH_SUCCESS;
            }
        }

        return SPLUNK_AUTH_UNAUTHORIZED;
    }
    else {
        return SPLUNK_AUTH_MISSING_CRED;
    }

    return SPLUNK_AUTH_SUCCESS;
}

static int process_hec_payload_ng(struct flb_http_request *request,
                                  struct flb_http_response *response,
                                  flb_sds_t tag,
                                  struct flb_splunk *ctx)
{
    int type = -1;
    int ret = 0;
    size_t size = 0;
    char *auth_header;

    type = HTTP_CONTENT_UNKNOWN;

    if (request->content_type != NULL) {
        if (strcasecmp(request->content_type, "application/json") == 0) {
            type = HTTP_CONTENT_JSON;
        }
        else if (strcasecmp(request->content_type, "text/plain") == 0) {
            type = HTTP_CONTENT_TEXT;
        }
        else {
            /* Not necessary to specify content-type for Splunk HEC. */
            flb_plg_debug(ctx->ins, "Mark as unknown type for ingested payloads");
        }
    }

    ret = flb_hash_table_get(request->headers, "authorization", 13, (void **)&auth_header, &size);
    if (ret != 0 && size > 0) {
        if (strncasecmp(auth_header, "Splunk ", 7) == 0) {
            ctx->ingested_auth_header = auth_header;
            ctx->ingested_auth_header_len = strlen(auth_header);
        }
    }

    if (request->body == NULL || cfl_sds_len(request->body) <= 0) {
        send_json_message_response_ng(response, 400, "{\"text\":\"No data\",\"code\":5}");

        return -2;
    }

    return handle_hec_payload(ctx, type, tag, request->body, cfl_sds_len(request->body));
}

static int process_hec_raw_payload_ng(struct flb_http_request *request,
                                      struct flb_http_response *response,
                                      flb_sds_t tag,
                                      struct flb_splunk *ctx)
{
    int ret = 0;
    size_t size = 0;
    char *auth_header;

    if (request->content_type == NULL) {
        send_response_ng(response, 400, "error: header 'Content-Type' is not set\n");

        return -1;
    }
    else if (strcasecmp(request->content_type, "text/plain") != 0) {
        /* Not necessary to specify content-type for Splunk HEC. */
        flb_plg_debug(ctx->ins, "Mark as unknown type for ingested payloads");
    }

    ret = flb_hash_table_get(request->headers, "authorization", 13, (void **)&auth_header, &size);
    if (ret != 0 && size > 0) {
        if (strncasecmp(auth_header, "Splunk ", 7) == 0) {
            ctx->ingested_auth_header = auth_header;
            ctx->ingested_auth_header_len = strlen(auth_header);
        }
    }

    if (request->body == NULL || cfl_sds_len(request->body) == 0) {
        send_json_message_response_ng(response, 400, "{\"text\":\"No data\",\"code\":5}");

        return -2;
    }

    /* Always handle as raw type of payloads here */
    return process_raw_payload_pack(ctx, tag, request->body, cfl_sds_len(request->body));
}

int splunk_prot_handle_ng(struct flb_http_request *request,
                          struct flb_http_response *response)
{
    struct flb_splunk *context;
    int                ret = -1;
    flb_sds_t          tag;

    context = (struct flb_splunk *) response->stream->user_data;

    if (request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {

        return -1;
    }

    if (request->method == HTTP_METHOD_GET) {
        /* Handle health monitoring of splunk hec endpoint for load balancers */
        if (strcasecmp(request->path, "/services/collector/health") == 0) {
            send_json_message_response_ng(response, 200, "{\"text\":\"Success\",\"code\":200}");
        }
        else {
            send_response_ng(response, 400, "error: invalid HTTP endpoint\n");
        }

        return 0;
    }

    /* Under services/collector endpoints are required for
     * authentication if provided splunk_token */
    ret = validate_auth_header_ng(context, request);

    if (ret < 0) {
        send_response_ng(response, 401, "error: unauthorized\n");

        if (ret == SPLUNK_AUTH_MISSING_CRED) {
            flb_plg_warn(context->ins, "missing credentials in request headers");
        }
        else if (ret == SPLUNK_AUTH_UNAUTHORIZED) {
            flb_plg_warn(context->ins, "wrong credentials in request headers");
        }

        return -1;
    }

    /* Handle every ingested payload cleanly */
    flb_log_event_encoder_reset(&context->log_encoder);

    if (request->method != HTTP_METHOD_POST) {
        /* HEAD, PUT, PATCH, and DELETE methods are prohibited to use.*/
        send_response_ng(response, 400, "error: invalid HTTP method\n");

        return -1;
    }

    tag = flb_sds_create(context->ins->tag);

    if (tag == NULL) {
        return -1;
    }

    if (strcasecmp(request->path, "/services/collector/raw/1.0") == 0 ||
        strcasecmp(request->path, "/services/collector/raw") == 0) {
        ret = process_hec_raw_payload_ng(request, response, tag, context);
        if (ret == -2) {
            /* Response already sent, skip further response */
            flb_sds_destroy(tag);
            return -1;
        }
        if (ret != 0) {
            send_json_message_response_ng(response, 400, "{\"text\":\"Invalid data format\",\"code\":6}");
            ret = -1;
        }
        else {
            send_json_message_response_ng(response, 200, "{\"text\":\"Success\",\"code\":0}");
            ret = 0;
        }
    }
    else if (strcasecmp(request->path, "/services/collector/event/1.0") == 0 ||
             strcasecmp(request->path, "/services/collector/event") == 0 ||
             strcasecmp(request->path, "/services/collector") == 0) {
        ret = process_hec_payload_ng(request, response, tag, context);
        if (ret == -2) {
            /* Response already sent, skip further response */
            flb_sds_destroy(tag);
            return -1;
        }
        if (ret != 0) {
            send_json_message_response_ng(response, 400, "{\"text\":\"Invalid data format\",\"code\":6}");
            ret = -1;
        }
        else {
            send_json_message_response_ng(response, 200, "{\"text\":\"Success\",\"code\":0}");
            ret = 0;
        }
    }
    else {
        send_response_ng(response, 400, "error: invalid HTTP endpoint\n");
        ret = -1;
    }

    flb_sds_destroy(tag);
    return ret;
}
