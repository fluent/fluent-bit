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
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include <monkey/monkey.h>
#include <monkey/mk_core.h>
#include <cmetrics/cmt_decode_opentelemetry.h>

#include <fluent-otel-proto/fluent-otel.h>
#include "opentelemetry.h"
#include "http_conn.h"

#define HTTP_CONTENT_JSON  0

static int otlp_pack_any_value(msgpack_packer *mp_pck,
                               Opentelemetry__Proto__Common__V1__AnyValue *body);

static int send_response(struct http_conn *conn, int http_status, char *message)
{
    int len;
    flb_sds_t out;
    size_t sent;

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

    /* We should check the outcome of this operation */
    flb_io_net_write(conn->connection,
                     (void *) out,
                     flb_sds_len(out),
                     &sent);

    flb_sds_destroy(out);

    return 0;
}

static int process_payload_metrics(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                   flb_sds_t tag,
                                   struct mk_http_session *session,
                                   struct mk_http_request *request)
{
    struct cfl_list  decoded_contexts;
    struct cfl_list *iterator;
    struct cmt      *context;
    size_t           offset;
    int              result;

    offset = 0;

    result = cmt_decode_opentelemetry_create(&decoded_contexts,
                                             request->data.data,
                                             request->data.len,
                                             &offset);

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        ctx->ins->event_type = FLB_INPUT_METRICS;

        cfl_list_foreach(iterator, &decoded_contexts) {
            context = cfl_list_entry(iterator, struct cmt, _head);

            result = flb_input_metrics_append(ctx->ins, NULL, 0, context);

            if (result != 0) {
                flb_plg_debug(ctx->ins, "could not ingest metrics context : %d", result);
            }
        }

        cmt_decode_opentelemetry_destroy(&decoded_contexts);
    }

    return 0;
}

static int process_payload_traces_proto(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                        flb_sds_t tag,
                                        struct mk_http_session *session,
                                        struct mk_http_request *request)
{
    struct ctrace *decoded_context;
    size_t         offset;
    int            result;

    offset = 0;
    result = ctr_decode_opentelemetry_create(&decoded_context,
                                             request->data.data,
                                             request->data.len,
                                             &offset);
    if (result == 0) {
        ctx->ins->event_type = FLB_INPUT_TRACES;
        result = flb_input_trace_append(ctx->ins, NULL, 0, decoded_context);
        ctr_decode_opentelemetry_destroy(decoded_context);
    }

    return result;
}

static int process_payload_raw_traces(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                      flb_sds_t tag,
                                      struct mk_http_session *session,
                                      struct mk_http_request *request)
{
    int ret;
    int root_type;
    char *out_buf = NULL;
    size_t out_size;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);

    /* Check if the incoming payload is a valid JSON message and convert it to msgpack */
    ret = flb_pack_json(request->data.data, request->data.len, &out_buf, &out_size, &root_type);

    if (ret == 0 && root_type == JSMN_OBJECT) {
        /* JSON found, pack it msgpack representation */
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
    }
    else {
        /* the content might be a binary payload or invalid JSON */
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, "trace", 5);
        msgpack_pack_str_with_body(&mp_pck, request->data.data, request->data.len);
    }

    /* release 'out_buf' if it was allocated */
    if (out_buf) {
        flb_free(out_buf);
    }

    ctx->ins->event_type = FLB_INPUT_LOGS;
    flb_input_log_append(ctx->ins, tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static int process_payload_traces(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                  flb_sds_t tag,
                                  struct mk_http_session *session,
                                  struct mk_http_request *request)
{
    int result;

    if (ctx->raw_traces) {
        result = process_payload_raw_traces(ctx, conn, tag, session, request);
    }
    else {
        result = process_payload_traces_proto(ctx, conn, tag, session, request);
    }

    return result;
}

static int otel_pack_string(msgpack_packer *mp_pck, char *str)
{
    return msgpack_pack_str_with_body(mp_pck, str, strlen(str));
}

static int otel_pack_bool(msgpack_packer *mp_pck, bool val)
{
    if (val) {
        return msgpack_pack_true(mp_pck);
    }
    else {
        return msgpack_pack_false(mp_pck);
    }
}

static int otel_pack_int(msgpack_packer *mp_pck, int val)
{
    return msgpack_pack_int64(mp_pck, val);
}

static int otel_pack_double(msgpack_packer *mp_pck, double val)
{
    return msgpack_pack_double(mp_pck, val);
}

static int otel_pack_kvlist(msgpack_packer *mp_pck,
                            Opentelemetry__Proto__Common__V1__KeyValueList *kv_list)
{
    int kv_index;
    int ret;
    char *key;
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    ret = msgpack_pack_map(mp_pck, kv_list->n_values);
    if (ret != 0) {
        return ret;
    }

    for (kv_index = 0; kv_index < kv_list->n_values && ret == 0; kv_index++) {
        key = kv_list->values[kv_index]->key;
        value = kv_list->values[kv_index]->value;

        ret = otel_pack_string(mp_pck, key);

        if(ret == 0) {
           ret = otlp_pack_any_value(mp_pck, value);
        }
    }

    return ret;
}

static int otel_pack_array(msgpack_packer *mp_pck,
                           Opentelemetry__Proto__Common__V1__ArrayValue *array)
{
    int ret;
    int array_index;

    for (array_index = 0; array_index < array->n_values && ret == 0; array_index++) {
        ret = otlp_pack_any_value(mp_pck, array->values[array_index]);
    }
    return ret;
}

static int otel_pack_bytes(msgpack_packer *mp_pck,
                           ProtobufCBinaryData bytes)
{
    return msgpack_pack_bin_with_body(mp_pck, bytes.data, bytes.len);
}

static int otlp_pack_any_value(msgpack_packer *mp_pck,
                               Opentelemetry__Proto__Common__V1__AnyValue *body)
{
    int result;

    result = -2;

    switch(body->value_case){
        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE:
            result = otel_pack_string(mp_pck, body->string_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE:
            result =  otel_pack_bool(mp_pck, body->bool_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE:
            result = otel_pack_int(mp_pck, body->int_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE:
            result = otel_pack_double(mp_pck, body->double_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE:
            result = otel_pack_array(mp_pck, body->array_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE:
            result = otel_pack_kvlist(mp_pck, body->kvlist_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE:
            result = otel_pack_bytes(mp_pck, body->bytes_value);
            break;

        default:
            break;
    }

    if (result == -2) {
        flb_error("[otel]: invalid value type in pack_any_value");
        result = -1;
    }

    return result;
}

static int binary_payload_to_msgpack(msgpack_packer *mp_pck,
                                     uint8_t *in_buf,
                                     size_t in_size)
{
    int ret;
    int resource_logs_index;
    int scope_log_index;
    int log_record_index;

    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *input_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **scope_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;
    Opentelemetry__Proto__Logs__V1__ResourceLogs **resource_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__LogRecord **log_records;
    Opentelemetry__Proto__Logs__V1__LogRecord *log_record;

    input_logs = opentelemetry__proto__collector__logs__v1__export_logs_service_request__unpack(NULL, in_size, in_buf);
    if (input_logs == NULL) {
        flb_error("[otel] Failed to unpack input logs");
        return -1;
    }

    resource_logs = input_logs->resource_logs;
    if (resource_logs == NULL) {
        flb_error("[otel] No resource logs found");
        return -1;
    }

    for (resource_logs_index = 0; resource_logs_index < input_logs->n_resource_logs; resource_logs_index++) {
        resource_log = resource_logs[resource_logs_index];
        scope_logs = resource_log->scope_logs;

        if (resource_log->n_scope_logs > 0 && scope_logs == NULL) {
            flb_error("[otel] No scope logs found");
            return -1;
        }

        for (scope_log_index = 0; scope_log_index < resource_log->n_scope_logs; scope_log_index++) {
            scope_log = scope_logs[scope_log_index];
            log_records = scope_log->log_records;

            if (log_records == NULL) {
                flb_error("[otel] No log records found");
                return -1;
            }

            for (log_record_index=0; log_record_index < scope_log->n_log_records; log_record_index++) {
                msgpack_pack_array(mp_pck, 2);
                flb_pack_time_now(mp_pck);

                log_record = log_records[log_record_index];

                ret = otlp_pack_any_value(mp_pck, log_record->body);

                if (ret != 0) {
                    flb_error("[otel] Failed to convert log record body");
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int get_token_length(jsmntok_t token){
    return token.end - token.start;
}

static char *get_value_from_token(jsmntok_t *tokens,
                                  const char *body,
                                  int pos){
    char *tmp;
    jsmntok_t token;
    int token_len;

    token = tokens[pos];
    token_len = get_token_length(token);

    tmp = flb_calloc(1, token_len + 1);
    tmp =  memcpy(tmp, body+token.start, token_len);

    return tmp;
}

static int json_payload_to_msgpack(msgpack_packer *mp_pck,
                                   const char *body,
                                   size_t len)
{
    int n_tokens;
    int token_index;
    int kv_index;
    int result;

    char *key;
    char *otel_value_type;
    char *otel_log_record;

    jsmn_parser parser;
    jsmntok_t tokens[1024];
    jsmntok_t token;

    result = 0;

    jsmn_init(&parser);
    n_tokens = jsmn_parse(&parser, body, len, tokens, 1024);

    if (n_tokens < 0) {
        flb_error("[otel] Failed to parse JSON payload, jsmn error %d", n_tokens);
        return -1;
    }

    // position 0 is the root object, skip it
    for (token_index = 1; token_index < n_tokens; token_index++) {
        token = tokens[token_index];

        switch (token.type) {

            case JSMN_OBJECT:
                for (kv_index=0; kv_index < token.size; kv_index++) {
                    key = get_value_from_token(tokens, body, token_index+kv_index+1);

                    if (strcmp(key, "body") == 0) {
                        otel_value_type = get_value_from_token(tokens, body, token_index+kv_index+3);
                        otel_log_record = get_value_from_token(tokens, body, token_index+kv_index+4);

                        msgpack_pack_array(mp_pck, 2);
                        flb_pack_time_now(mp_pck);

                        if (strcasecmp(otel_value_type, "stringvalue") == 0) {
                            result = otel_pack_string(mp_pck, otel_log_record);
                        }

                        else if (strcasecmp(otel_value_type, "intvalue") == 0) {
                            result = otel_pack_int(mp_pck, atoi(otel_log_record));
                        }

                        else if (strcasecmp(otel_value_type, "doublevalue") == 0) {
                            result = otel_pack_double(mp_pck, atof(otel_log_record));
                        }

                        else if (strcasecmp(otel_value_type, "boolvalue") == 0) {
                            if (strcasecmp(otel_log_record, "true") == 0) {
                                result = otel_pack_bool(mp_pck, true);
                            } else {
                                result = otel_pack_bool(mp_pck, false);
                            }
                        }

                        else if (strcasecmp(otel_value_type, "bytesvalue") == 0){
                            result = otel_pack_string(mp_pck, otel_log_record);
                        }

                        flb_free(otel_value_type);
                        flb_free(otel_log_record);
                    }

                    flb_free(key);
                }
                break;

            default:
                break;
        }
    }
    return result;
}

static int process_payload_logs(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                flb_sds_t tag,
                                struct mk_http_session *session,
                                struct mk_http_request *request)
{
    int ret;
    char *out_buf = NULL;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Check if the incoming payload is a valid JSON message and convert it to msgpack */
    if (strncasecmp(request->content_type.data,
                    "application/json",
                    request->content_type.len) == 0) {
        ret = json_payload_to_msgpack(&mp_pck, request->data.data, request->data.len);
    }
    else if (strncasecmp(request->content_type.data,
                         "application/x-protobuf",
                         request->content_type.len) == 0) {
        ret =  binary_payload_to_msgpack(&mp_pck, (uint8_t *)request->data.data, request->data.len);
    }
    else {
        flb_error("[otel] Unsupported content type %.*s", request->content_type.len, request->content_type.data);
        ret = -1;
    }

    /* release 'out_buf' if it was allocated */
    if (out_buf) {
        flb_free(out_buf);
    }

    ctx->ins->event_type = FLB_INPUT_LOGS;

    flb_input_log_append(ctx->ins, tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);
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
int opentelemetry_prot_handle(struct flb_opentelemetry *ctx, struct http_conn *conn,
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

    if (strcmp(uri, "/v1/metrics") != 0 &&
        strcmp(uri, "/v1/traces") != 0  &&
        strcmp(uri, "/v1/logs") != 0) {

        send_response(conn, 400, "error: invalid endpoint\n");
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
        send_response(conn, 400, "error: invalid HTTP method\n");
        return -1;
    }

    if (strcmp(uri, "/v1/metrics") == 0) {
        ret = process_payload_metrics(ctx, conn, tag, session, request);
    }
    else if (strcmp(uri, "/v1/traces") == 0) {
        ret = process_payload_traces(ctx, conn, tag, session, request);
    }
    else if (strcmp(uri, "/v1/logs") == 0) {
        ret = process_payload_logs(ctx, conn, tag, session, request);
    }

    mk_mem_free(uri);
    flb_sds_destroy(tag);
    send_response(conn, ctx->successful_response_code, NULL);
    return ret;
}

/*
 * Handle an incoming request which has resulted in an http parser error.
 */
int opentelemetry_prot_handle_error(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                    struct mk_http_session *session,
                                    struct mk_http_request *request)
{
    send_response(conn, 400, "error: invalid request\n");
    return -1;
}
