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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <fluent-otel-proto/fluent-otel.h>


#include "opentelemetry.h"
//#include "opentelemetry_logs.h"
#include "opentelemetry_utils.h"

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

static int process_json_payload_log_records_entry(struct flb_opentelemetry *ctx,
                                                  struct flb_log_event_encoder *encoder,
                                                  msgpack_object *log_records_object)
{
    int                 result;
    int                 body_type;
    char                timestamp_str[32];
    msgpack_object_map *log_records_entry;
    msgpack_object     *timestamp_object;
    uint64_t            timestamp_uint64;
    msgpack_object     *metadata_object;
    msgpack_object     *body_object;
    msgpack_object     *observed_time_unix_nano = NULL;
    msgpack_object     *severity_number = NULL;
    msgpack_object     *severity_text = NULL;
    msgpack_object     *trace_id = NULL;
    msgpack_object     *span_id = NULL;
    struct flb_time     timestamp;


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

    /* observedTimeUnixNano (yes, we do it again) */
    result = find_map_entry_by_key(log_records_entry, "observedTimeUnixNano", 0, FLB_TRUE);
    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "observed_time_unix_nano", 0, FLB_TRUE);
    }
    else if (result >= 0) {
        observed_time_unix_nano = &log_records_entry->ptr[result].val;
    }

    /* severityNumber */
    result = find_map_entry_by_key(log_records_entry, "severityNumber", 0, FLB_TRUE);
    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "severity_number", 0, FLB_TRUE);
    }
    if (result >= 0) {
        severity_number = &log_records_entry->ptr[result].val;
    }

    /* severityText */
    result = find_map_entry_by_key(log_records_entry, "severityText", 0, FLB_TRUE);
    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "severity_text", 0, FLB_TRUE);
    }
    if (result >= 0) {
        severity_text = &log_records_entry->ptr[result].val;
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

    /* traceId */
    result = find_map_entry_by_key(log_records_entry, "traceId", 0, FLB_TRUE);
    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "trace_id", 0, FLB_TRUE);
    }
    if (result >= 0) {
        trace_id = &log_records_entry->ptr[result].val;
    }

    /* spanId */
    result = find_map_entry_by_key(log_records_entry, "spanId", 0, FLB_TRUE);
    if (result == -1) {
        result = find_map_entry_by_key(log_records_entry, "span_id", 0, FLB_TRUE);
    }
    if (result >= 0) {
        span_id = &log_records_entry->ptr[result].val;
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

    flb_log_event_encoder_dynamic_field_reset(&encoder->metadata);
    result = flb_log_event_encoder_begin_map(encoder, FLB_LOG_EVENT_METADATA);
    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_append_string(encoder, FLB_LOG_EVENT_METADATA, ctx->logs_metadata_key, flb_sds_len(ctx->logs_metadata_key));
        flb_log_event_encoder_begin_map(encoder, FLB_LOG_EVENT_METADATA);

        if (observed_time_unix_nano != NULL && observed_time_unix_nano->type == MSGPACK_OBJECT_STR) {
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

            flb_log_event_encoder_append_metadata_values(encoder,
                                                         FLB_LOG_EVENT_STRING_VALUE("observed_timestamp", 18),
                                                         FLB_LOG_EVENT_INT64_VALUE(timestamp_uint64));
        }

        if (severity_number != NULL) {
            flb_log_event_encoder_append_metadata_values(encoder,
                                                         FLB_LOG_EVENT_STRING_VALUE("severity_number", 15),
                                                         FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(severity_number));
        }

        if (severity_text != NULL && severity_text->type == MSGPACK_OBJECT_STR) {
            flb_log_event_encoder_append_metadata_values(encoder,
                                                         FLB_LOG_EVENT_STRING_VALUE("severity_text", 13),
                                                         FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(severity_text));
        }

        if (metadata_object != NULL) {
            flb_log_event_encoder_append_string(encoder, FLB_LOG_EVENT_METADATA, "attributes", 10);
            result = json_payload_append_converted_kvlist(encoder, FLB_LOG_EVENT_METADATA, metadata_object);
        }

        if (trace_id != NULL && (trace_id->type == MSGPACK_OBJECT_STR || trace_id->type == MSGPACK_OBJECT_BIN)) {
            flb_log_event_encoder_append_metadata_values(encoder,
                                                         FLB_LOG_EVENT_STRING_VALUE("trace_id", 8),
                                                         FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(trace_id));
        }

        if (span_id != NULL && (span_id->type == MSGPACK_OBJECT_STR || span_id->type == MSGPACK_OBJECT_BIN)) {
            flb_log_event_encoder_append_metadata_values(encoder,
                                                         FLB_LOG_EVENT_STRING_VALUE("span_id", 7),
                                                         FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(span_id));
        }

        flb_log_event_encoder_commit_map(encoder, FLB_LOG_EVENT_METADATA);

    }
    flb_log_event_encoder_commit_map(encoder, FLB_LOG_EVENT_METADATA);

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
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "could not append body");
            flb_log_event_encoder_rollback_record(encoder);
            result = -4;
            return result;
        }
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


static int process_json_payload_resource_logs_entry(struct flb_opentelemetry *ctx,
                                                    struct flb_log_event_encoder *encoder,
                                                    size_t resource_logs_index,
                                                    msgpack_object *resource_logs_object)
{
    int ret;
    int result;
    size_t index;
    msgpack_object       obj;
    msgpack_object_map   *resource = NULL;
    msgpack_object       *resource_attr = NULL;
    msgpack_object_map   *resource_logs_entry = NULL;
    msgpack_object       *scope = NULL;
    msgpack_object_array *scope_logs;

    if (resource_logs_object->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected resourceLogs entry type");
        return -2;
    }

    /* get 'resource' and resource['attributes'] */
    result = find_map_entry_by_key(&resource_logs_object->via.map, "resource", 0, FLB_TRUE);
    if (result >= 0) {
        obj = resource_logs_object->via.map.ptr[result].val;
        if (obj.type == MSGPACK_OBJECT_MAP) {
            resource = &obj.via.map;
            result = find_map_entry_by_key(resource, "attributes", 0, FLB_TRUE);
            if (result >= 0) {
                obj = resource->ptr[result].val;
                if (obj.type == MSGPACK_OBJECT_ARRAY) {
                    resource_attr = &obj;
                }
            }
        }
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

    for (index = 0 ; index < scope_logs->size ; index++) {
        /*
         * Add the information about OTLP metadata, we do this by registering
         * a group-type record.
         */
        flb_log_event_encoder_group_init(encoder);

        /* pack internal schema */
        ret = flb_log_event_encoder_append_metadata_values(encoder,
                                                            FLB_LOG_EVENT_STRING_VALUE("schema", 6),
                                                            FLB_LOG_EVENT_STRING_VALUE("otlp", 4),
                                                            FLB_LOG_EVENT_STRING_VALUE("resource_id", 11),
                                                            FLB_LOG_EVENT_INT64_VALUE(resource_logs_index),
                                                            FLB_LOG_EVENT_STRING_VALUE("scope_id", 8),
                                                            FLB_LOG_EVENT_INT64_VALUE(index));
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "could not set group content metadata");
            return -2;
        }

        /* Resource key */
        flb_log_event_encoder_append_body_string(encoder, "resource", 8);

        /* start resource value (map) */
        flb_log_event_encoder_body_begin_map(encoder);

        /* Check if we have OTel resource attributes */
        if (resource_attr) {
            flb_log_event_encoder_append_body_string(encoder, "attributes", 10);
            result = json_payload_append_converted_kvlist(encoder,
                                                          FLB_LOG_EVENT_BODY,
                                                          resource_attr);
        }

        /* resource dropped_attributers_count */
        result = find_map_entry_by_key(resource, "droppedAttributesCount", 0, FLB_TRUE);
        if (result >= 0) {
            obj = resource->ptr[result].val;
            flb_log_event_encoder_append_body_values(encoder,
                                                     FLB_LOG_EVENT_CSTRING_VALUE("dropped_attributes_count"),
                                                     FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&obj));
        }

        /* close resource map */
        flb_log_event_encoder_body_commit_map(encoder);

        /* scope metadata */
        scope = NULL;
        obj = scope_logs->ptr[index];
        if (obj.type == MSGPACK_OBJECT_MAP) {
            result = find_map_entry_by_key(&obj.via.map, "scope", 0, FLB_TRUE);
            if (result >= 0) {
                if (obj.via.map.ptr[result].val.type == MSGPACK_OBJECT_MAP) {
                    scope = &obj.via.map.ptr[result].val;
                }
            }
        }

        if (scope) {
            /*
             * if the scope is found, process every expected key one by one to avoid
             * wrongly ingested items.
             */

            /* append scope key */
            flb_log_event_encoder_append_body_string(encoder, "scope", 5);

            /* scope map value */
            flb_log_event_encoder_body_begin_map(encoder);

            /* scope name */
            result = find_map_entry_by_key(&scope->via.map, "name", 0, FLB_TRUE);
            if (result >= 0) {
                obj = scope->via.map.ptr[result].val;
                if (obj.type == MSGPACK_OBJECT_STR) {
                    flb_log_event_encoder_append_body_values(encoder,
                                                             FLB_LOG_EVENT_CSTRING_VALUE("name"),
                                                             FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&obj));
                }
            }

            /* scope version */
            result = find_map_entry_by_key(&scope->via.map, "version", 0, FLB_TRUE);
            if (result >= 0) {
                obj = scope->via.map.ptr[result].val;
                if (obj.type == MSGPACK_OBJECT_STR) {
                    flb_log_event_encoder_append_body_values(encoder,
                                                            FLB_LOG_EVENT_CSTRING_VALUE("version"),
                                                            FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&obj));
                }
            }

            /* scope attributes */
            result = find_map_entry_by_key(&scope->via.map, "attributes", 0, FLB_TRUE);
            if (result >= 0) {
                obj = scope->via.map.ptr[result].val;
                if (obj.type == MSGPACK_OBJECT_ARRAY) {
                    flb_log_event_encoder_append_body_string(encoder, "attributes", 10);
                    result = json_payload_append_converted_kvlist(encoder,
                                                                FLB_LOG_EVENT_BODY,
                                                                &obj);
                    if (result != 0) {
                        return -2;
                    }
                }
            }

            flb_log_event_encoder_commit_map(encoder, FLB_LOG_EVENT_BODY);
        }

        flb_log_event_encoder_commit_map(encoder, FLB_LOG_EVENT_BODY);

        flb_log_event_encoder_group_header_end(encoder);

        result = process_json_payload_scope_logs_entry(
                                                      ctx,
                                                      encoder,
                                                      &scope_logs->ptr[index]);
        flb_log_event_encoder_group_end(encoder);
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
                    index,
                    &resource_logs->ptr[index]);
    }

    return result;
}

/*
 * Process the OTLP-JSON payload and convert it to msgpack
 * ---------------------------------------------------
 */
static int process_json(struct flb_opentelemetry *ctx,
                        struct flb_log_event_encoder *encoder,
                        char *tag, size_t tag_len,
                        const char *body, size_t len)
{
    int              result;
    int              root_type;
    size_t           msgpack_body_length;
    char            *msgpack_body;
    msgpack_unpacked unpacked_root;
    size_t           offset;

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

/*
 * OTLP encoding functions to pack the log records as msgpack
 * ----------------------------------------------------------
 */
static int otlp_pack_any_value(msgpack_packer *mp_pck, Opentelemetry__Proto__Common__V1__AnyValue *body);

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
                                     char *tag, size_t tag_len,
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

            flb_log_event_encoder_group_end(encoder);

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

/*
 * Main function used from opentelemetry_prot.c to process logs either in JSON or Protobuf format.
 * -----------------------------------------------------------------------------------------------
 */
int opentelemetry_process_logs(struct flb_opentelemetry *ctx,
                               flb_sds_t content_type,
                               flb_sds_t tag,
                               size_t tag_len,
                               void *data, size_t size)
{
    int ret = -1;
    int is_proto = FLB_FALSE; /* default to JSON */
    char *buf;
    uint8_t *payload;
    uint64_t payload_size;
    struct flb_log_event_encoder *encoder;

    buf = (unsigned char *) data;
    payload = data;
    payload_size = size;

    /* Detect the type of payload */
    if (content_type) {
        if (strcasecmp(content_type, "application/json") == 0) {
            if (buf[0] != '{') {
                flb_plg_error(ctx->ins, "Invalid JSON payload");
                return -1;
            }
            is_proto = FLB_FALSE;
        }
        else if (strcasecmp(content_type, "application/protobuf") == 0 ||
                 strcasecmp(content_type, "application/grpc") == 0 ||
                 strcasecmp(content_type, "application/x-protobuf") == 0) {
            is_proto = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "Unsupported content type %s", content_type);
            return -1;
        }
    }

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (encoder == NULL) {
        return -1;
    }

    if (is_proto == FLB_TRUE) {
        ret = binary_payload_to_msgpack(ctx, encoder,
                                        tag, tag_len,
                                        (uint8_t *) payload, payload_size);
    }
    else {
        /* The content is likely OTel JSON */
        ret = process_json(ctx, encoder,
                           tag, tag_len,
                           payload, payload_size);
    }
    if (ret != 0) {
        if (is_proto) {
            flb_plg_error(ctx->ins, "failed to process logs from protobuf payload");
        }
        else {
            flb_plg_error(ctx->ins, "failed to process logs from JSON payload");
        }
    }
    else {
        ret = flb_input_log_append(ctx->ins,
                                   tag,
                                   flb_sds_len(tag),
                                   encoder->output_buffer,
                                   encoder->output_length);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to append logs to the input buffer");
        }
    }

    flb_log_event_encoder_destroy(encoder);
    return ret;
}
