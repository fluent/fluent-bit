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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <monkey/monkey.h>
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

static int binary_payload_to_msgpack(struct flb_log_event_encoder *encoder,
                                     uint8_t *in_buf,
                                     size_t in_size)
{
    int ret;
    msgpack_packer  packer;
    msgpack_sbuffer buffer;
    int resource_logs_index;
    int scope_log_index;
    int log_record_index;

    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *input_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **scope_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;
    Opentelemetry__Proto__Logs__V1__ResourceLogs **resource_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__LogRecord **log_records;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

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
                ret = flb_log_event_encoder_begin_record(encoder);

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_set_current_timestamp(encoder);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = otel_pack_kvarray(
                            &packer,
                            log_records[log_record_index]->attributes,
                            log_records[log_record_index]->n_attributes);

                    if (ret != 0) {
                        flb_error("[otel] Failed to convert log record attributes");

                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        ret = flb_log_event_encoder_set_metadata_from_raw_msgpack(
                                encoder,
                                buffer.data,
                                buffer.size);
                    }

                    msgpack_sbuffer_clear(&buffer);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = otlp_pack_any_value(
                            &packer,
                            log_records[log_record_index]->body);

                    if (ret != 0) {
                        flb_error("[otel] Failed to convert log record body");

                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        if (log_records[log_record_index]->body->value_case ==
                            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
                            ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                                    encoder,
                                    buffer.data,
                                    buffer.size);
                        }
                        else {
                            ret = flb_log_event_encoder_append_body_values(
                                    encoder,
                                    FLB_LOG_EVENT_CSTRING_VALUE("message"),
                                    FLB_LOG_EVENT_MSGPACK_RAW_VALUE(buffer.data, buffer.size));
                        }
                    }

                    msgpack_sbuffer_clear(&buffer);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_commit_record(encoder);
                }
                else {
                    flb_error("[otel] marshalling error");

                    msgpack_sbuffer_destroy(&buffer);

                    return -1;
                }
            }
        }
    }

    msgpack_sbuffer_destroy(&buffer);

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
        ret = binary_payload_to_msgpack(encoder, (uint8_t *) request->data.data, request->data.len);
    }
    else {
        flb_error("[otel] Unsupported content type %.*s", (int)request->content_type.len, request->content_type.data);

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
    char *original_data;
    size_t original_data_size;
    char *uncompressed_data;
    size_t uncompressed_data_size;

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

    original_data = request->data.data;
    original_data_size = request->data.len;

    ret = opentelemetry_prot_uncompress(session, request,
                                        &uncompressed_data,
                                        &uncompressed_data_size);

    if (ret > 0) {
        request->data.data = uncompressed_data;
        request->data.len = uncompressed_data_size;
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

    if (uncompressed_data != NULL) {
        flb_free(uncompressed_data);
    }

    request->data.data = original_data;
    request->data.len = original_data_size;

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
