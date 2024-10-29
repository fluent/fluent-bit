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
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <monkey/monkey.h>
#include <fluent-bit/http_server/flb_http_server.h>

#include <monkey/mk_core.h>
#include <cmetrics/cmt_decode_opentelemetry.h>

#include <fluent-otel-proto/fluent-otel.h>
#include "opentelemetry.h"
#include "http_conn.h"

#define HTTP_CONTENT_JSON  0

static int json_payload_append_converted_value(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object);

static int json_payload_append_converted_array(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object);

static int json_payload_append_converted_kvlist(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object);

static int json_payload_to_msgpack(struct flb_opentelemetry *ctx,
                                   struct flb_log_event_encoder *encoder,
                                   const char *body,
                                   size_t len);

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
    flb_io_net_write(conn->connection,
                     (void *) out,
                     flb_sds_len(out),
                     &sent);

    flb_sds_destroy(out);

    return 0;
}

static int process_payload_metrics(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                   flb_sds_t tag,
                                   size_t tag_len,
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
        cfl_list_foreach(iterator, &decoded_contexts) {
            context = cfl_list_entry(iterator, struct cmt, _head);

            result = flb_input_metrics_append(ctx->ins, tag, tag_len, context);

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
                                        size_t tag_len,
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
        result = flb_input_trace_append(ctx->ins, tag, tag_len, decoded_context);
        ctr_decode_opentelemetry_destroy(decoded_context);
    }

    return result;
}

static int process_payload_raw_traces(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                      flb_sds_t tag,
                                      size_t tag_len,
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
    ret = flb_pack_json(request->data.data, request->data.len,
                        &out_buf, &out_size, &root_type, NULL);

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

    flb_input_log_append(ctx->ins, tag, tag_len, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static int process_payload_traces(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                  flb_sds_t tag,
                                  size_t tag_len,
                                  struct mk_http_session *session,
                                  struct mk_http_request *request)
{
    int result;

    if (ctx->raw_traces) {
        result = process_payload_raw_traces(ctx, conn, tag, tag_len, session, request);
    }
    else {
        result = process_payload_traces_proto(ctx, conn, tag, tag_len, session, request);
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

static int otel_pack_kvarray(msgpack_packer *mp_pck,
                             Opentelemetry__Proto__Common__V1__KeyValue **kv_array,
                             size_t kv_count)
{
    int result;
    int index;

    result = msgpack_pack_map(mp_pck, kv_count);

    if (result != 0) {
        return result;
    }

    for (index = 0; index < kv_count && result == 0; index++) {
        result = otel_pack_string(mp_pck, kv_array[index]->key);

        if(result == 0) {
           result = otlp_pack_any_value(mp_pck, kv_array[index]->value);
        }
    }

    return result;
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

    ret = msgpack_pack_array(mp_pck, array->n_values);

    if (ret != 0) {
        return ret;
    }

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

/* https://opentelemetry.io/docs/specs/otel/logs/data-model/#log-and-event-record-definition */
static int otel_pack_v1_metadata(struct flb_opentelemetry *ctx,
                                 msgpack_packer *mp_pck,
                                 struct Opentelemetry__Proto__Logs__V1__LogRecord *log_record,
                                 Opentelemetry__Proto__Resource__V1__Resource *resource,
                                 Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    int ret;
    int len;
    struct flb_mp_map_header mh;
    struct flb_mp_map_header otlp_mh;

    flb_mp_map_header_init(&otlp_mh, mp_pck);

    len = flb_sds_len(ctx->logs_metadata_key);

    /* otlp key start */
    flb_mp_map_header_append(&otlp_mh);

    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, ctx->logs_metadata_key, len);

    flb_mp_map_header_init(&mh, mp_pck);

    flb_mp_map_header_append(&mh);
    msgpack_pack_str(mp_pck, 18);
    msgpack_pack_str_body(mp_pck, "observed_timestamp", 18);
    msgpack_pack_uint64(mp_pck, log_record->observed_time_unix_nano);

    /* Value of 0 indicates unknown or missing timestamp. */
    if (log_record->time_unix_nano != 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 9);
        msgpack_pack_str_body(mp_pck, "timestamp", 9);
        msgpack_pack_uint64(mp_pck, log_record->time_unix_nano);
    }

    /* https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber */
    if (log_record->severity_number >= 1 && log_record->severity_number <= 24) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 15);
        msgpack_pack_str_body(mp_pck, "severity_number", 15);
        msgpack_pack_uint64(mp_pck, log_record->severity_number);
    }

    if (log_record->severity_text != NULL && strlen(log_record->severity_text) > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 13);
        msgpack_pack_str_body(mp_pck, "severity_text", 13);
        msgpack_pack_str(mp_pck, strlen(log_record->severity_text));
        msgpack_pack_str_body(mp_pck, log_record->severity_text, strlen(log_record->severity_text));
    }

    if (log_record->n_attributes > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "attributes", 10);
        ret = otel_pack_kvarray(mp_pck,
                                log_record->attributes,
                                log_record->n_attributes);
        if (ret != 0) {
            return ret;
        }
    }

    if (log_record->trace_id.len > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 8);
        msgpack_pack_str_body(mp_pck, "trace_id", 8);
        ret = otel_pack_bytes(mp_pck, log_record->trace_id);
        if (ret != 0) {
            return ret;
        }
    }

    if (log_record->span_id.len > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 7);
        msgpack_pack_str_body(mp_pck, "span_id", 7);
        ret = otel_pack_bytes(mp_pck, log_record->span_id);
        if (ret != 0) {
            return ret;
        }
    }

    flb_mp_map_header_append(&mh);
    msgpack_pack_str(mp_pck, 11);
    msgpack_pack_str_body(mp_pck, "trace_flags", 11);
    msgpack_pack_uint8(mp_pck, (uint8_t) log_record->flags & 0xff);

    flb_mp_map_header_end(&mh);

    /* otlp key end */
    flb_mp_map_header_end(&otlp_mh);

    return 0;
}

static int binary_payload_to_msgpack(struct flb_opentelemetry *ctx,
                                     struct flb_log_event_encoder *encoder,
                                     uint8_t *in_buf,
                                     size_t in_size)
{
    int ret;
    int len;
    int resource_logs_index;
    int scope_log_index;
    int log_record_index;
    struct flb_mp_map_header mh;
    struct flb_mp_map_header mh_tmp;
    struct flb_time tm;

    /* record buffer and packer */
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;

    /* metadata buffer and packer */
    msgpack_sbuffer mp_sbuf_meta;
    msgpack_packer  mp_pck_meta;

    /* OTel proto suff */
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *input_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **scope_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;
    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope;

    Opentelemetry__Proto__Logs__V1__ResourceLogs **resource_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__LogRecord **log_records;
    Opentelemetry__Proto__Resource__V1__Resource *resource;

    /* initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_sbuffer_init(&mp_sbuf_meta);
    msgpack_packer_init(&mp_pck_meta, &mp_sbuf_meta, msgpack_sbuffer_write);

    /* unpack logs from protobuf payload */
    input_logs = opentelemetry__proto__collector__logs__v1__export_logs_service_request__unpack(NULL, in_size, in_buf);
    if (input_logs == NULL) {
        flb_plg_warn(ctx->ins, "failed to unpack input logs from OpenTelemetry payload");
        ret = -1;
        goto binary_payload_to_msgpack_end;
    }

    resource_logs = input_logs->resource_logs;
    if (resource_logs == NULL) {
        flb_plg_warn(ctx->ins, "no resource logs found");
        ret = -1;
        goto binary_payload_to_msgpack_end;
    }

    for (resource_logs_index = 0; resource_logs_index < input_logs->n_resource_logs; resource_logs_index++) {
        resource_log = resource_logs[resource_logs_index];
        resource = resource_log->resource;
        scope_logs = resource_log->scope_logs;

        if (resource_log->n_scope_logs > 0 && scope_logs == NULL) {
            flb_plg_warn(ctx->ins, "no scope logs found");
            ret = -1;
            goto binary_payload_to_msgpack_end;
        }

        for (scope_log_index = 0; scope_log_index < resource_log->n_scope_logs; scope_log_index++) {
            scope_log = scope_logs[scope_log_index];
            log_records = scope_log->log_records;

            if (log_records == NULL) {
                flb_plg_warn(ctx->ins, "no log records found");
                ret = -1;
                goto binary_payload_to_msgpack_end;
            }

            flb_log_event_encoder_group_init(encoder);

            /* pack schema (internal) */
            ret = flb_log_event_encoder_append_metadata_values(encoder,
                                                               FLB_LOG_EVENT_STRING_VALUE("schema", 6),
                                                               FLB_LOG_EVENT_STRING_VALUE("otlp", 4),
                                                               FLB_LOG_EVENT_STRING_VALUE("resource_id", 11),
                                                               FLB_LOG_EVENT_INT64_VALUE(resource_logs_index),
                                                               FLB_LOG_EVENT_STRING_VALUE("scope_id", 8),
                                                               FLB_LOG_EVENT_INT64_VALUE(scope_log_index));


            flb_mp_map_header_init(&mh, &mp_pck);

            /* Resource */
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(&mp_pck, 8);
            msgpack_pack_str_body(&mp_pck, "resource", 8);

            flb_mp_map_header_init(&mh_tmp, &mp_pck);

            /* look for OTel resource attributes */
            if (resource->n_attributes > 0 && resource->attributes) {
                flb_mp_map_header_append(&mh_tmp);
                msgpack_pack_str(&mp_pck, 10);
                msgpack_pack_str_body(&mp_pck, "attributes", 10);

                ret = otel_pack_kvarray(&mp_pck,
                                        resource->attributes,
                                        resource->n_attributes);
                if (ret != 0) {
                    return ret;
                }
            }

            if (resource->dropped_attributes_count > 0) {
                flb_mp_map_header_append(&mh_tmp);
                msgpack_pack_str(&mp_pck, 24);
                msgpack_pack_str_body(&mp_pck, "dropped_attributes_count", 24);
                msgpack_pack_uint64(&mp_pck, resource->dropped_attributes_count);
            }

            flb_mp_map_header_end(&mh_tmp);

            if (resource_log->schema_url) {
                flb_mp_map_header_append(&mh);
                msgpack_pack_str(&mp_pck, 10);
                msgpack_pack_str_body(&mp_pck, "schema_url", 10);

                len = strlen(resource_log->schema_url);
                msgpack_pack_str(&mp_pck, len);
                msgpack_pack_str_body(&mp_pck, resource_log->schema_url, len);
            }

            /* scope */
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(&mp_pck, 5);
            msgpack_pack_str_body(&mp_pck, "scope", 5);

            /* Scope */
            scope = scope_log->scope;
            if (scope && (scope->name || scope->version || scope->n_attributes > 0)) {
                flb_mp_map_header_init(&mh_tmp, &mp_pck);

                if (scope->name && strlen(scope->name) > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 4);
                    msgpack_pack_str_body(&mp_pck, "name", 4);

                    len = strlen(scope->name);
                    msgpack_pack_str(&mp_pck, len);
                    msgpack_pack_str_body(&mp_pck, scope->name, len);
                }
                if (scope->version && strlen(scope->version) > 0) {
                    flb_mp_map_header_append(&mh_tmp);

                    msgpack_pack_str(&mp_pck, 7);
                    msgpack_pack_str_body(&mp_pck, "version", 7);

                    len = strlen(scope->version);
                    msgpack_pack_str(&mp_pck, len);
                    msgpack_pack_str_body(&mp_pck, scope->version, len);
                }

                if (scope->n_attributes > 0 && scope->attributes) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "attributes", 10);
                    ret = otel_pack_kvarray(&mp_pck,
                                            scope->attributes,
                                            scope->n_attributes);
                    if (ret != 0) {
                        return ret;
                    }
                }

                if (scope->dropped_attributes_count > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 24);
                    msgpack_pack_str_body(&mp_pck, "dropped_attributes_count", 24);
                    msgpack_pack_uint64(&mp_pck, scope->dropped_attributes_count);
                }

                flb_mp_map_header_end(&mh_tmp);
            }

            flb_mp_map_header_end(&mh);

            ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                            encoder,
                            mp_sbuf.data,
                            mp_sbuf.size);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(ctx->ins, "could not set group content metadata");
                goto binary_payload_to_msgpack_end;
            }
            flb_log_event_encoder_group_header_end(encoder);

            msgpack_sbuffer_clear(&mp_sbuf);

            for (log_record_index=0; log_record_index < scope_log->n_log_records; log_record_index++) {
                ret = flb_log_event_encoder_begin_record(encoder);

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    if (log_records[log_record_index]->time_unix_nano > 0) {
                        flb_time_from_uint64(&tm, log_records[log_record_index]->time_unix_nano);
                        ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
                    }
                    else {
                        ret = flb_log_event_encoder_set_current_timestamp(encoder);
                    }
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                     msgpack_sbuffer_clear(&mp_sbuf_meta);
                     ret = otel_pack_v1_metadata(ctx, &mp_pck_meta, log_records[log_record_index], resource, scope_log->scope);
                     if (ret != 0) {
                        flb_plg_error(ctx->ins, "failed to convert log record");
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        ret = flb_log_event_encoder_set_metadata_from_raw_msgpack(
                                encoder,
                                mp_sbuf_meta.data,
                                mp_sbuf_meta.size);
                    }

                    msgpack_sbuffer_clear(&mp_sbuf_meta);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = otlp_pack_any_value(
                            &mp_pck,
                            log_records[log_record_index]->body);

                    if (ret != 0) {
                        flb_plg_error(ctx->ins, "failed to convert log record body");
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        if (log_records[log_record_index]->body->value_case ==
                            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
                            ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                                    encoder,
                                    mp_sbuf.data,
                                    mp_sbuf.size);
                        }
                        else {
                            ret = flb_log_event_encoder_append_body_values(
                                    encoder,
                                    FLB_LOG_EVENT_CSTRING_VALUE("message"),
                                    FLB_LOG_EVENT_MSGPACK_RAW_VALUE(mp_sbuf.data, mp_sbuf.size));
                        }
                    }

                    msgpack_sbuffer_clear(&mp_sbuf);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_commit_record(encoder);
                }
                else {
                    flb_plg_error(ctx->ins, "marshalling error");
                    goto binary_payload_to_msgpack_end;
                }
            }

            flb_log_event_encoder_group_end(encoder);

        }
    }

 binary_payload_to_msgpack_end:
    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_sbuffer_destroy(&mp_sbuf_meta);
    if (input_logs) {
        opentelemetry__proto__collector__logs__v1__export_logs_service_request__free_unpacked(
                                            input_logs, NULL);
    }

    if (ret != 0) {
        return -1;
    }

    return 0;
}

static int find_map_entry_by_key(msgpack_object_map *map,
                                 char *key,
                                 size_t match_index,
                                 int case_insensitive)
{
    size_t  match_count;
    int     result;
    int     index;

    match_count = 0;

    for (index = 0 ; index < (int) map->size ; index++) {
        if (map->ptr[index].key.type == MSGPACK_OBJECT_STR) {
            if (case_insensitive) {
                result = strncasecmp(map->ptr[index].key.via.str.ptr,
                                     key,
                                     map->ptr[index].key.via.str.size);
            }
            else {
                result = strncmp(map->ptr[index].key.via.str.ptr,
                                 key,
                                 map->ptr[index].key.via.str.size);
            }

            if (result == 0) {
                if (match_count == match_index) {
                    return index;
                }

                match_count++;
            }
        }
    }

    return -1;
}

static int json_payload_get_wrapped_value(msgpack_object *wrapper,
                                          msgpack_object **value,
                                          int            *type)
{
    int                 internal_type;
    msgpack_object     *kv_value;
    msgpack_object_str *kv_key;
    msgpack_object_map *map;

    if (wrapper->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    map = &wrapper->via.map;
    kv_value = NULL;
    internal_type = -1;

    if (map->size == 1) {
        if (map->ptr[0].key.type == MSGPACK_OBJECT_STR) {
            kv_value = &map->ptr[0].val;
            kv_key = &map->ptr[0].key.via.str;

            if (strncasecmp(kv_key->ptr, "stringValue",  kv_key->size) == 0 ||
                strncasecmp(kv_key->ptr, "string_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_STR;
            }
            else if (strncasecmp(kv_key->ptr, "boolValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "bool_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_BOOLEAN;
            }
            else if (strncasecmp(kv_key->ptr, "intValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "int_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_POSITIVE_INTEGER;
            }
            else if (strncasecmp(kv_key->ptr, "doubleValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "double_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_FLOAT;
            }
            else if (strncasecmp(kv_key->ptr, "bytesValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "bytes_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_BIN;
            }
            else if (strncasecmp(kv_key->ptr, "arrayValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "array_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_ARRAY;
            }
            else if (strncasecmp(kv_key->ptr, "kvlistValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "kvlist_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_MAP;
            }
        }
    }

    if (internal_type != -1) {
        if (type != NULL) {
            *type  = internal_type;
        }

        if (value != NULL) {
            *value = kv_value;
        }

        if (kv_value->type == MSGPACK_OBJECT_MAP) {
            map = &kv_value->via.map;

            if (map->size == 1) {
                kv_value = &map->ptr[0].val;
                kv_key = &map->ptr[0].key.via.str;

                if (strncasecmp(kv_key->ptr, "values", kv_key->size) == 0) {
                    if (value != NULL) {
                        *value = kv_value;
                    }
                }
                else {
                    return -3;
                }
            }
        }
    }
    else {
        return -2;
    }

    return 0;
}

static int json_payload_append_unwrapped_value(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object,
            int *encoder_result)
{
    char            temporary_buffer[33];
    int             unwrap_value;
    int             result;
    msgpack_object *value;
    int             type;

    result = json_payload_get_wrapped_value(object,
                                            &value,
                                            &type);

    if (result == 0) {
        unwrap_value = FLB_FALSE;

        if (type == MSGPACK_OBJECT_STR) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_BOOLEAN) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            if (value->type == MSGPACK_OBJECT_STR) {
                memset(temporary_buffer, 0, sizeof(temporary_buffer));

                if (value->via.str.size < sizeof(temporary_buffer)) {
                    strncpy(temporary_buffer,
                            value->via.str.ptr,
                            value->via.str.size);
                }
                else {
                    strncpy(temporary_buffer,
                            value->via.str.ptr,
                            sizeof(temporary_buffer) - 1);
                }

                result = flb_log_event_encoder_append_int64(
                            encoder,
                            target_field,
                            strtoll(temporary_buffer, NULL, 10));
            }
            else {
                unwrap_value = FLB_TRUE;
            }
        }
        else if (type == MSGPACK_OBJECT_FLOAT) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_BIN) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_ARRAY) {
            result = json_payload_append_converted_array(encoder,
                                                         target_field,
                                                         value);
        }
        else if (type == MSGPACK_OBJECT_MAP) {
            result = json_payload_append_converted_kvlist(encoder,
                                                          target_field,
                                                          value);
        }
        else {
            return -2;
        }

        if (unwrap_value) {
            result = json_payload_append_converted_value(encoder,
                                                         target_field,
                                                         value);
        }

        *encoder_result = result;

        return 0;
    }
    else {
        return -1;
    }

    return -1;
}


static int json_payload_append_converted_map(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object)
{
    int                 encoder_result;
    int                 result;
    size_t              index;
    msgpack_object_map *map;

    map = &object->via.map;

    result = json_payload_append_unwrapped_value(
                encoder,
                target_field,
                object,
                &encoder_result);

    if (result == 0 && encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
        return result;
    }

    result = flb_log_event_encoder_begin_map(encoder, target_field);

    for (index = 0 ;
         index < map->size &&
         result == FLB_EVENT_ENCODER_SUCCESS;
         index++) {
        result = json_payload_append_converted_value(
                    encoder,
                    target_field,
                    &map->ptr[index].key);

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = json_payload_append_converted_value(
                        encoder,
                        target_field,
                        &map->ptr[index].val);
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_map(encoder, target_field);
    }
    else {
        flb_log_event_encoder_rollback_map(encoder, target_field);
    }

    return result;
}

static int json_payload_append_converted_array(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object)
{
    int                   result;
    size_t                index;
    msgpack_object_array *array;

    array = &object->via.array;

    result = flb_log_event_encoder_begin_array(encoder, target_field);

    for (index = 0 ;
         index < array->size &&
         result == FLB_EVENT_ENCODER_SUCCESS;
         index++) {
        result = json_payload_append_converted_value(
                    encoder,
                    target_field,
                    &array->ptr[index]);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_array(encoder, target_field);
    }
    else {
        flb_log_event_encoder_rollback_array(encoder, target_field);
    }

    return result;
}

static int json_payload_append_converted_kvlist(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object)
{
    int                   value_index;
    int                   key_index;
    int                   result;
    size_t                index;
    msgpack_object_array *array;
    msgpack_object_map   *entry;

    array = &object->via.array;

    result = flb_log_event_encoder_begin_map(encoder, target_field);

    for (index = 0 ;
         index < array->size &&
         result == FLB_EVENT_ENCODER_SUCCESS;
         index++) {

        if (array->ptr[index].type != MSGPACK_OBJECT_MAP) {
            result = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
        }
        else {
            entry = &array->ptr[index].via.map;

            key_index = find_map_entry_by_key(entry, "key", 0, FLB_TRUE);

            if (key_index == -1) {
                result = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                value_index = find_map_entry_by_key(entry, "value", 0, FLB_TRUE);
            }

            if (value_index == -1) {
                result = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = json_payload_append_converted_value(
                            encoder,
                            target_field,
                            &entry->ptr[key_index].val);
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = json_payload_append_converted_value(
                            encoder,
                            target_field,
                            &entry->ptr[value_index].val);
            }
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_map(encoder, target_field);
    }
    else {
        flb_log_event_encoder_rollback_map(encoder, target_field);
    }

    return result;
}

static int json_payload_append_converted_value(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object)
{
    int result;

    result = FLB_EVENT_ENCODER_SUCCESS;

    switch (object->type) {
        case MSGPACK_OBJECT_BOOLEAN:
            result = flb_log_event_encoder_append_boolean(
                        encoder,
                        target_field,
                        object->via.boolean);
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            result = flb_log_event_encoder_append_uint64(
                        encoder,
                        target_field,
                        object->via.u64);
            break;
        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            result = flb_log_event_encoder_append_int64(
                        encoder,
                        target_field,
                        object->via.i64);
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            result = flb_log_event_encoder_append_double(
                        encoder,
                        target_field,
                        object->via.f64);
            break;

        case MSGPACK_OBJECT_STR:
            result = flb_log_event_encoder_append_string(
                        encoder,
                        target_field,
                        (char *) object->via.str.ptr,
                        object->via.str.size);

            break;

        case MSGPACK_OBJECT_BIN:
            result = flb_log_event_encoder_append_binary(
                        encoder,
                        target_field,
                        (char *) object->via.bin.ptr,
                        object->via.bin.size);
            break;

        case MSGPACK_OBJECT_ARRAY:
            result = json_payload_append_converted_array(
                        encoder,
                        target_field,
                        object);
            break;

        case MSGPACK_OBJECT_MAP:
            result = json_payload_append_converted_map(
                        encoder,
                        target_field,
                        object);

            break;

        default:
            break;
    }

    return result;
}

static int process_json_payload_log_records_entry(
        struct flb_opentelemetry *ctx,
        struct flb_log_event_encoder *encoder,
        msgpack_object *log_records_object)
{
    msgpack_object_map *log_records_entry;
    char                timestamp_str[32];
    msgpack_object     *timestamp_object;
    uint64_t            timestamp_uint64;
    msgpack_object     *metadata_object;
    msgpack_object     *body_object;
    int                 body_type;
    struct flb_time     timestamp;
    int                 result;

    if (log_records_object->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected logRecords entry type");

        return -4;
    }

    log_records_entry = &log_records_object->via.map;

    result = find_map_entry_by_key(log_records_entry, "timeUnixNano", 0, FLB_TRUE);

    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "time_unix_nano", 0, FLB_TRUE);
    }

    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "observedTimeUnixNano", 0, FLB_TRUE);
    }

    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "observed_time_unix_nano", 0, FLB_TRUE);
    }

    if (result == -1) {
        flb_plg_info(ctx->ins, "neither timeUnixNano nor observedTimeUnixNano found");

        flb_time_get(&timestamp);
    }
    else {
        timestamp_object = &log_records_entry->ptr[result].val;

        if (timestamp_object->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            timestamp_uint64 = timestamp_object->via.u64;
        }
        else if (timestamp_object->type == MSGPACK_OBJECT_STR) {
            memset(timestamp_str, 0, sizeof(timestamp_str));

            if (timestamp_object->via.str.size < sizeof(timestamp_str)) {
                strncpy(timestamp_str,
                        timestamp_object->via.str.ptr,
                        timestamp_object->via.str.size);
            }
            else {
                strncpy(timestamp_str,
                        timestamp_object->via.str.ptr,
                        sizeof(timestamp_str) - 1);
            }

            timestamp_uint64 = strtoul(timestamp_str, NULL, 10);
        }
        else {
            flb_plg_error(ctx->ins, "unexpected timeUnixNano type");

            return -4;
        }

        flb_time_from_uint64(&timestamp, timestamp_uint64);
    }


    result = find_map_entry_by_key(log_records_entry, "attributes", 0, FLB_TRUE);

    if (result == -1) {
        flb_plg_debug(ctx->ins, "attributes missing");

        metadata_object = NULL;
    }
    else {
        if (log_records_entry->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
            flb_plg_error(ctx->ins, "unexpected attributes type");

            return -4;
        }

        metadata_object = &log_records_entry->ptr[result].val;
    }

    result = find_map_entry_by_key(log_records_entry, "body", 0, FLB_TRUE);

    if (result == -1) {
        flb_plg_info(ctx->ins, "body missing");

        body_object = NULL;
    }
    else {
        if (log_records_entry->ptr[result].val.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "unexpected body type");

            return -4;
        }

        body_object = &log_records_entry->ptr[result].val;
    }

    result = flb_log_event_encoder_begin_record(encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(encoder, &timestamp);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS &&
        metadata_object != NULL) {
        flb_log_event_encoder_dynamic_field_reset(&encoder->metadata);

        result = json_payload_append_converted_kvlist(
                    encoder,
                    FLB_LOG_EVENT_METADATA,
                    metadata_object);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS &&
        body_object != NULL) {
        result = json_payload_get_wrapped_value(body_object, NULL, &body_type);

        if (result != 0 || body_type == MSGPACK_OBJECT_MAP) {
            flb_log_event_encoder_dynamic_field_reset(&encoder->body);
        }
        else {
            flb_log_event_encoder_append_cstring(
                 encoder,
                 FLB_LOG_EVENT_BODY,
                 "log");
        }

        result = json_payload_append_converted_value(
                    encoder,
                    FLB_LOG_EVENT_BODY,
                    body_object);
    }

    result = flb_log_event_encoder_dynamic_field_flush(&encoder->body);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(encoder);
    }
    else {
        flb_plg_error(ctx->ins, "log event encoder failure : %d", result);

        flb_log_event_encoder_rollback_record(encoder);

        result = -4;
    }

    return result;
}

static int process_json_payload_scope_logs_entry(
        struct flb_opentelemetry *ctx,
        struct flb_log_event_encoder *encoder,
        msgpack_object *scope_logs_object)
{
    msgpack_object_map   *scope_logs_entry;
    msgpack_object_array *log_records;
    int                   result;
    size_t                index;

    if (scope_logs_object->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected scopeLogs entry type");

        return -3;
    }

    scope_logs_entry = &scope_logs_object->via.map;

    result = find_map_entry_by_key(scope_logs_entry, "logRecords", 0, FLB_TRUE);

    if (result == -1) {
        result = find_map_entry_by_key(scope_logs_entry, "logRecords", 0, FLB_TRUE);

        if (result == -1) {
            flb_plg_error(ctx->ins, "scopeLogs missing");

            return -3;
        }
    }

    if (scope_logs_entry->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        flb_plg_error(ctx->ins, "unexpected logRecords type");

        return -3;
    }

    log_records = &scope_logs_entry->ptr[result].val.via.array;

    result = 0;

    for (index = 0 ; index < log_records->size ; index++) {
        result = process_json_payload_log_records_entry(
                    ctx,
                    encoder,
                    &log_records->ptr[index]);
    }

    return result;
}


static int process_json_payload_resource_logs_entry(
            struct flb_opentelemetry *ctx,
            struct flb_log_event_encoder *encoder,
            msgpack_object *resource_logs_object)
{
    msgpack_object_map   *resource_logs_entry;
    msgpack_object_array *scope_logs;
    int                   result;
    size_t                index;


    if (resource_logs_object->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected resourceLogs entry type");

        return -2;
    }

    resource_logs_entry = &resource_logs_object->via.map;

    result = find_map_entry_by_key(resource_logs_entry, "scopeLogs", 0, FLB_TRUE);

    if (result == -1) {
        result = find_map_entry_by_key(resource_logs_entry, "scope_logs", 0, FLB_TRUE);

        if (result == -1) {
            flb_plg_error(ctx->ins, "scopeLogs missing");

            return -2;
        }
    }

    if (resource_logs_entry->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        flb_plg_error(ctx->ins, "unexpected scopeLogs type");

        return -2;
    }

    scope_logs = &resource_logs_entry->ptr[result].val.via.array;

    result = 0;

    for (index = 0 ; index < scope_logs->size ; index++) {
        result = process_json_payload_scope_logs_entry(
                    ctx,
                    encoder,
                    &scope_logs->ptr[index]);
    }

    return result;
}

static int process_json_payload_root(struct flb_opentelemetry *ctx,
                                     struct flb_log_event_encoder *encoder,
                                     msgpack_object *root_object)
{
    msgpack_object_array *resource_logs;
    int                   result;
    size_t                index;
    msgpack_object_map   *root;

    if (root_object->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected root object type");

        return -1;
    }

    root = &root_object->via.map;

    result = find_map_entry_by_key(root, "resourceLogs", 0, FLB_TRUE);

    if (result == -1) {
        result = find_map_entry_by_key(root, "resource_logs", 0, FLB_TRUE);

        if (result == -1) {
            flb_plg_error(ctx->ins, "resourceLogs missing");

            return -1;
        }
    }

    if (root->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        flb_plg_error(ctx->ins, "unexpected resourceLogs type");

        return -1;
    }

    resource_logs = &root->ptr[result].val.via.array;

    result = 0;

    for (index = 0 ; index < resource_logs->size ; index++) {
        result = process_json_payload_resource_logs_entry(
                    ctx,
                    encoder,
                    &resource_logs->ptr[index]);
    }

    return result;
}

/* This code is definitely not complete and beyond fishy, it needs to be
 * refactored.
 */
static int json_payload_to_msgpack(struct flb_opentelemetry *ctx,
                                   struct flb_log_event_encoder *encoder,
                                   const char *body,
                                   size_t len)
{
    size_t           msgpack_body_length;
    msgpack_unpacked unpacked_root;
    char            *msgpack_body;
    int              root_type;
    size_t           offset;
    int              result;

    result = flb_pack_json(body, len, &msgpack_body, &msgpack_body_length,
                           &root_type, NULL);

    if (result != 0) {
        flb_plg_error(ctx->ins, "json to msgpack conversion error");
    }
    else {
        msgpack_unpacked_init(&unpacked_root);

        offset = 0;
        result = msgpack_unpack_next(&unpacked_root,
                                     msgpack_body,
                                     msgpack_body_length,
                                     &offset);

        if (result == MSGPACK_UNPACK_SUCCESS) {
            result = process_json_payload_root(ctx,
                                               encoder,
                                               &unpacked_root.data);
        }
        else {
            result = -1;
        }

        msgpack_unpacked_destroy(&unpacked_root);

        flb_free(msgpack_body);
    }

    return result;
}

static int process_payload_logs(struct flb_opentelemetry *ctx, struct http_conn *conn,
                                flb_sds_t tag,
                                size_t tag_len,
                                struct mk_http_session *session,
                                struct mk_http_request *request)
{
    struct flb_log_event_encoder *encoder;
    int                           ret;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);

    if (encoder == NULL) {
        return -1;
    }

    /* Check if the incoming payload is a valid JSON message and convert it to msgpack */
    if (strncasecmp(request->content_type.data,
                    "application/json",
                    request->content_type.len) == 0) {
        ret = json_payload_to_msgpack(ctx,
                                      encoder,
                                      request->data.data,
                                      request->data.len);
    }
    else if (strncasecmp(request->content_type.data,
                         "application/x-protobuf",
                         request->content_type.len) == 0) {
        ret = binary_payload_to_msgpack(ctx, encoder, (uint8_t *) request->data.data, request->data.len);
    }
    else {
        flb_error("[otel] Unsupported content type %.*s", (int)request->content_type.len, request->content_type.data);

        ret = -1;
    }

    if (ret == 0) {
        ret = flb_input_log_append(ctx->ins,
                                   tag,
                                   tag_len,
                                   encoder->output_buffer,
                                   encoder->output_length);
    }

    flb_log_event_encoder_destroy(encoder);

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

static \
int uncompress_zlib(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    flb_error("[opentelemetry] unsupported compression format");

    return -1;
}

static \
int uncompress_zstd(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    flb_error("[opentelemetry] unsupported compression format");

    return -1;
}

static \
int uncompress_deflate(char **output_buffer,
                       size_t *output_size,
                       char *input_buffer,
                       size_t input_size)
{
    flb_error("[opentelemetry] unsupported compression format");

    return -1;
}

static \
int uncompress_snappy(char **output_buffer,
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

static \
int uncompress_gzip(char **output_buffer,
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

int opentelemetry_prot_uncompress(struct mk_http_session *session,
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
            else if (strncasecmp(header->val.data, "zlib", 4) == 0) {
                return uncompress_zlib(output_buffer,
                                       output_size,
                                       request->data.data,
                                       request->data.len);
            }
            else if (strncasecmp(header->val.data, "zstd", 4) == 0) {
                return uncompress_zstd(output_buffer,
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
            else if (strncasecmp(header->val.data, "deflate", 4) == 0) {
                return uncompress_deflate(output_buffer,
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
int opentelemetry_prot_handle(struct flb_opentelemetry *ctx, struct http_conn *conn,
                              struct mk_http_session *session,
                              struct mk_http_request *request)
{
    int i;
    int ret = -1;
    int len;
    char *uri;
    char *qs;
    char *out_chunked = NULL;
    size_t out_chunked_size = 0;
    off_t diff;
    size_t tag_len;
    flb_sds_t tag;
    char *original_data = NULL;
    size_t original_data_size;
    char *uncompressed_data = NULL;
    size_t uncompressed_data_size;
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

    /* Try to match a query string, so we can remove it */
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
        flb_sds_cat(tag, uri + 1, len - 1);

        /* Sanitize, only allow alphanum chars */
        for (i = 0; i < flb_sds_len(tag); i++) {
            if (!isalnum(tag[i]) && tag[i] != '_' && tag[i] != '.') {
                tag[i] = '_';
            }
        }
    }

    tag_len = flb_sds_len(tag);

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

    original_data = request->data.data;
    original_data_size = request->data.len;

    /* check if the request comes with chunked transfer encoding */
    if (mk_http_parser_is_content_chunked(&session->parser)) {
        out_chunked = NULL;
        out_chunked_size = 0;

        /* decode the chunks */
        ret = mk_http_parser_chunked_decode(&session->parser,
                                            conn->buf_data,
                                            conn->buf_len,
                                            &out_chunked,
                                            &out_chunked_size);
        if (ret == -1) {
            flb_sds_destroy(tag);
            mk_mem_free(uri);
            send_response(conn, 400, "error: invalid chunked data\n");
            if (uncompressed_data != NULL) {
                flb_free(uncompressed_data);
            }
            return -1;
        }
        else {
            request->data.data = out_chunked;
            request->data.len = out_chunked_size;
        }
    }

    ret = opentelemetry_prot_uncompress(session, request,
                                        &uncompressed_data,
                                        &uncompressed_data_size);

    if (ret > 0) {
        request->data.data = uncompressed_data;
        request->data.len = uncompressed_data_size;
    }

    if (strcmp(uri, "/v1/metrics") == 0) {
        ret = process_payload_metrics(ctx, conn, tag, tag_len, session, request);
    }
    else if (strcmp(uri, "/v1/traces") == 0) {
        ret = process_payload_traces(ctx, conn, tag, tag_len, session, request);
    }
    else if (strcmp(uri, "/v1/logs") == 0) {
        ret = process_payload_logs(ctx, conn, tag, tag_len, session, request);
    }

    request->data.data = original_data;
    request->data.len = original_data_size;

    if (uncompressed_data != NULL) {
        flb_free(uncompressed_data);
    }

    if (out_chunked != NULL) {
        mk_mem_free(out_chunked);
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

static int send_grpc_response_ng(struct flb_http_response *response,
                                 uint8_t *message_buffer,
                                 size_t message_length,
                                 int grpc_status,
                                 char *grpc_message)
{
    char      grpc_status_as_string[16];
    uint32_t  wire_message_length;
    size_t    body_buffer_size;
    cfl_sds_t body_buffer;

    body_buffer_size = 5 + message_length;

    if (body_buffer_size < 65) {
        body_buffer_size = 65;
    }

    body_buffer = cfl_sds_create_size(body_buffer_size);

    if (body_buffer == NULL) {
        return -1;
    }

    sprintf(grpc_status_as_string, "%u", grpc_status);

    wire_message_length = (uint32_t) message_length;

    cfl_sds_cat(body_buffer, "\x00----", 5);

    ((uint8_t *) body_buffer)[1] = (wire_message_length & 0xFF000000) >> 24;
    ((uint8_t *) body_buffer)[2] = (wire_message_length & 0x00FF0000) >> 16;
    ((uint8_t *) body_buffer)[3] = (wire_message_length & 0x0000FF00) >> 8;
    ((uint8_t *) body_buffer)[4] = (wire_message_length & 0x000000FF) >> 0;

    if (message_buffer != NULL) {
        cfl_sds_cat(body_buffer, (char *) message_buffer, message_length);
    }

    flb_http_response_set_status(response, 200);

    flb_http_response_set_body(response,
                                (unsigned char *) body_buffer,
                                5 + message_length);

    flb_http_response_set_header(response,
                                 "content-type",     0,
                                 "application/grpc", 0);

    flb_http_response_set_trailer_header(response,
                                         "grpc-status", 0,
                                         grpc_status_as_string, 0);

    flb_http_response_set_trailer_header(response,
                                         "grpc-message", 0,
                                         grpc_message,   0);

    flb_http_response_commit(response);

    cfl_sds_destroy(body_buffer);

    return 0;
}

static int send_export_logs_service_response_ng(struct flb_http_response *response,
                                                int status)
{
    uint8_t                                                             *message_buffer;
    size_t                                                               message_length;
    const char                                                          *grpc_message;
    int                                                                  grpc_status;
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceResponse message;

    if (status == 0) {
        opentelemetry__proto__collector__logs__v1__export_logs_service_response__init(&message);

        message_length = opentelemetry__proto__collector__logs__v1__export_logs_service_response__get_packed_size(&message);

        message_buffer = flb_calloc(message_length, sizeof(uint8_t));

        if (message_buffer == NULL) {
            return -1;
        }

        opentelemetry__proto__collector__logs__v1__export_logs_service_response__pack(&message, message_buffer);

        grpc_status  = 0;
        grpc_message = "";
    }
    else {
        grpc_status  = 2; /* gRPC UNKNOWN */
        grpc_message = "Serialization error.";
        message_buffer = NULL;
        message_length = 0;
    }

    send_grpc_response_ng(response, message_buffer, message_length, grpc_status, (char *) grpc_message);

    if (message_buffer != NULL) {
        flb_free(message_buffer);
    }

    return 0;
}

static int send_export_metrics_service_response_ng(struct flb_http_response *response,
                                                   int status)
{
    uint8_t                                                                   *message_buffer;
    size_t                                                                     message_length;
    const char                                                                *grpc_message;
    int                                                                        grpc_status;
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceResponse message;

    if (status == 0) {
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__init(&message);

        message_length = opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__get_packed_size(&message);

        message_buffer = flb_calloc(message_length, sizeof(uint8_t));

        if (message_buffer == NULL) {
            return -1;
        }

        opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__pack(&message, message_buffer);

        grpc_status  = 0;
        grpc_message = "-";
    }
    else {
        grpc_status  = 2; /* gRPC UNKNOWN */
        grpc_message = "Serialization error.";
        message_buffer = NULL;
        message_length = 0;
    }

    send_grpc_response_ng(response, message_buffer, message_length, grpc_status, (char *) grpc_message);

    if (message_buffer != NULL) {
        flb_free(message_buffer);
    }

    return 0;
}

static int send_export_traces_service_response_ng(struct flb_http_response *response,
                                                  int status)
{
    uint8_t                                                               *message_buffer;
    size_t                                                                 message_length;
    const char                                                            *grpc_message;
    int                                                                    grpc_status;
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceResponse message;

    if (status == 0) {
        opentelemetry__proto__collector__trace__v1__export_trace_service_response__init(&message);

        message_length = opentelemetry__proto__collector__trace__v1__export_trace_service_response__get_packed_size(&message);

        message_buffer = flb_calloc(message_length, sizeof(uint8_t));

        if (message_buffer == NULL) {
            return -1;
        }

        opentelemetry__proto__collector__trace__v1__export_trace_service_response__pack(&message, message_buffer);

        grpc_status  = 0;
        grpc_message = "-";
    }
    else {
        grpc_status  = 2; /* gRPC UNKNOWN */
        grpc_message = "Serialization error.";
        message_buffer = NULL;
        message_length = 0;
    }

    send_grpc_response_ng(response, message_buffer, message_length, grpc_status, (char *) grpc_message);

    if (message_buffer != NULL) {
        flb_free(message_buffer);
    }

    return 0;
}
static int process_payload_metrics_ng(struct flb_opentelemetry *ctx,
                                      flb_sds_t tag,
                                      struct flb_http_request *request,
                                      struct flb_http_response *response)
{
    struct cfl_list  decoded_contexts;
    struct cfl_list *iterator;
    struct cmt      *context;
    size_t           offset;
    int              result;

    offset = 0;

    if (request->content_type == NULL) {
        flb_error("[otel] content type missing");

        return -1;
    }

    if (strcasecmp(request->content_type, "application/grpc") == 0) {
        if (cfl_sds_len(request->body) < 5) {
            return -1;
        }

        result = cmt_decode_opentelemetry_create(&decoded_contexts,
                                                 &request->body[5],
                                                 cfl_sds_len(request->body) - 5,
                                                 &offset);
    }
    else if (strcasecmp(request->content_type, "application/x-protobuf") == 0 ||
             strcasecmp(request->content_type, "application/json") == 0) {
        result = cmt_decode_opentelemetry_create(&decoded_contexts,
                                                request->body,
                                                cfl_sds_len(request->body),
                                                &offset);
    }
    else {
        flb_plg_error(ctx->ins, "Unsupported content type %s", request->content_type);

        return -1;
    }

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(iterator, &decoded_contexts) {
            context = cfl_list_entry(iterator, struct cmt, _head);

            result = flb_input_metrics_append(ctx->ins, NULL, 0, context);

            if (result != 0) {
                flb_plg_debug(ctx->ins, "could not ingest metrics context : %d", result);
            }
        }

        cmt_decode_opentelemetry_destroy(&decoded_contexts);
    }
    else {
        flb_plg_warn(ctx->ins, "non-success cmetrics opentelemetry decode result %d", result);
        return -1;
    }

    return 0;
}


static int process_payload_traces_proto_ng(struct flb_opentelemetry *ctx,
                                           flb_sds_t tag,
                                           struct flb_http_request *request,
                                           struct flb_http_response *response)
{
    struct ctrace *decoded_context;
    size_t         offset;
    int            result;

    offset = 0;

    if (request->content_type == NULL) {
        flb_error("[otel] content type missing");

        return -1;
    }

    if (strcasecmp(request->content_type, "application/grpc") == 0) {
        if (cfl_sds_len(request->body) < 5) {
            return -1;
        }

        result = ctr_decode_opentelemetry_create(&decoded_context,
                                                 &request->body[5],
                                                 cfl_sds_len(request->body) - 5,
                                                 &offset);
    }
    else if (strcasecmp(request->content_type, "application/x-protobuf") == 0 ||
             strcasecmp(request->content_type, "application/json") == 0) {
        result = ctr_decode_opentelemetry_create(&decoded_context,
                                                request->body,
                                                cfl_sds_len(request->body),
                                                &offset);
    }
    else {
        flb_plg_error(ctx->ins, "Unsupported content type %s", request->content_type);

        return -1;
    }

    if (result == 0) {
        result = flb_input_trace_append(ctx->ins, NULL, 0, decoded_context);
        ctr_decode_opentelemetry_destroy(decoded_context);
    }
    else {
        flb_plg_warn(ctx->ins, "non-success ctraces opentelemetry decode result %d", result);
    }

    return result;
}

static int process_payload_raw_traces_ng(struct flb_opentelemetry *ctx,
                                         flb_sds_t tag,
                                         struct flb_http_request *request,
                                         struct flb_http_response *response)
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
    ret = flb_pack_json(request->body, cfl_sds_len(request->body),
                        &out_buf, &out_size, &root_type, NULL);

    if (ret == 0 && root_type == JSMN_OBJECT) {
        /* JSON found, pack it msgpack representation */
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
    }
    else {
        /* the content might be a binary payload or invalid JSON */
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, "trace", 5);
        msgpack_pack_str_with_body(&mp_pck, request->body, cfl_sds_len(request->body));
    }

    /* release 'out_buf' if it was allocated */
    if (out_buf) {
        flb_free(out_buf);
    }

    flb_input_log_append(ctx->ins, tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static int process_payload_traces_ng(struct flb_opentelemetry *ctx,
                                     flb_sds_t tag,
                                     struct flb_http_request *request,
                                     struct flb_http_response *response)
{
    int result;

    if (ctx->raw_traces) {
        result = process_payload_raw_traces_ng(ctx, tag, request, response);
    }
    else {
        result = process_payload_traces_proto_ng(ctx, tag, request, response);
    }

    return result;
}

static int process_payload_logs_ng(struct flb_opentelemetry *ctx,
                                   flb_sds_t tag,
                                   struct flb_http_request *request,
                                   struct flb_http_response *response)
{
    struct flb_log_event_encoder *encoder;
    int                           ret;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);

    if (encoder == NULL) {
        return -1;
    }

    if (request->content_type == NULL) {
        flb_error("[otel] content type missing");

        ret = -1;
    }
    else if (strcasecmp(request->content_type, "application/json") == 0) {
        ret = json_payload_to_msgpack(ctx,
                                      encoder,
                                      request->body,
                                      cfl_sds_len(request->body));
    }
    else if (strcasecmp(request->content_type, "application/x-protobuf") == 0) {
        ret = binary_payload_to_msgpack(ctx,
                                        encoder,
                                        (uint8_t *) request->body,
                                        cfl_sds_len(request->body));
    }
    else if (strcasecmp(request->content_type, "application/grpc") == 0) {
        if (cfl_sds_len(request->body) < 5) {
            return -1;
        }

        ret = binary_payload_to_msgpack(ctx,
                                        encoder,
                                        &((uint8_t *) request->body)[5],
                                        (cfl_sds_len(request->body)) - 5);
    }
    else {
        flb_plg_error(ctx->ins, "Unsupported content type %s", request->content_type);

        ret = -1;
    }

    if (ret == 0) {
        ret = flb_input_log_append(ctx->ins,
                                   tag,
                                   flb_sds_len(tag),
                                   encoder->output_buffer,
                                   encoder->output_length);
    }

    flb_log_event_encoder_destroy(encoder);

    return ret;
}


static int send_export_service_response_ng(struct flb_http_response *response,
                                           int result,
                                           char payload_type)
{
    switch (payload_type) {
    case 'M':
        return send_export_metrics_service_response_ng(response, result);
    case 'T':
        return send_export_traces_service_response_ng(response, result);
    case 'L':
        return send_export_logs_service_response_ng(response, result);
    default:
        return -1;
    }
}

int opentelemetry_prot_handle_ng(struct flb_http_request *request,
                                 struct flb_http_response *response)
{
    char                            payload_type;
    int                             grpc_request;
    struct flb_opentelemetry       *context;
    int                             result = -1;
    flb_sds_t                       tag = NULL;

    context = (struct flb_opentelemetry *) response->stream->user_data;

    if (request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    if (strcmp(request->path, "/v1/metrics") == 0 ||
        strcmp(request->path, "/v1/traces") == 0  ||
        strcmp(request->path, "/v1/logs") == 0) {
        grpc_request = FLB_FALSE;
    }
    else if(strcmp(request->path, "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.traces.v1.TracesService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.logs.v1.LogsService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.metric.v1.MetricService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.trace.v1.TraceService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.log.v1.LogService/Export") == 0) {

        grpc_request = FLB_TRUE;
    }
    else {
        send_response_ng(response, 400, "error: invalid endpoint\n");
        return -1;
    }

    /* ToDo: Fix me */
    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {
        return -1;
    }

    if (request->method != HTTP_METHOD_POST) {
        send_response_ng(response, 400, "error: invalid HTTP method\n");
        return -1;
    }

    if (strcmp(request->path, "/v1/metrics") == 0 ||
        strcmp(request->path, "/opentelemetry.proto.collector.metric.v1.MetricService/Export") == 0 ||
        strcmp(request->path, "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export") == 0) {
        payload_type = 'M';
        if (context->tag_from_uri == FLB_TRUE) {
            tag = flb_sds_create("v1_metrics");
        }
        else {
            tag = flb_sds_create(context->ins->tag);
        }
        result = process_payload_metrics_ng(context, tag, request, response);
    }
    else if (strcmp(request->path, "/v1/traces") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.trace.v1.TraceService/Export") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.traces.v1.TracesService/Export") == 0) {
        payload_type = 'T';
        if (context->tag_from_uri == FLB_TRUE) {
            tag = flb_sds_create("v1_traces");
        }
        else {
            tag = flb_sds_create(context->ins->tag);
        }
        result = process_payload_traces_ng(context, tag, request, response);
    }
    else if (strcmp(request->path, "/v1/logs") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.log.v1.LogService/Export") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.logs.v1.LogsService/Export") == 0) {
        payload_type = 'L';
        if (context->tag_from_uri == FLB_TRUE) {
            tag = flb_sds_create("v1_logs");
        }
        else {
            tag = flb_sds_create(context->ins->tag);
        }
        result = process_payload_logs_ng(context, tag, request, response);
    }

    if (grpc_request) {
        send_export_service_response_ng(response, result, payload_type);
    }
    else {
        if (result == 0) {
            send_response_ng(response, context->successful_response_code, NULL);
        }
        else {
            send_response_ng(response, 400, "invalid request: deserialisation error\n");
        }
    }

    flb_sds_destroy(tag);

    return result;
}
