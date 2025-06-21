/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-otel-proto/fluent-otel.h>
#include "flb_opentelemetry_utils.h"

#define FLB_OTEL_LOGS_METADATA_KEY "otlp"

enum flb_otel_logs_error_code {
    FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE = 1,
    FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_ENTRY_TYPE,
    FLB_OTEL_LOGS_ERR_SCOPELOGS_MISSING,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE,
    FLB_OTEL_LOGS_ERR_GROUP_METADATA,
    FLB_OTEL_LOGS_ERR_SCOPE_METADATA,
    FLB_OTEL_LOGS_ERR_SCOPE_KVLIST,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE,
    FLB_OTEL_LOGS_ERR_MISSING_TIMESTAMP,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE,
    FLB_OTEL_LOGS_ERR_MISSING_LOGRECORDS,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE,
    FLB_OTEL_LOGS_ERR_ENCODER_FAILURE,
    FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE
};

static char *flb_otel_logs_error_msg(int err_code)
{
    switch (err_code) {
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE:
            return "unexpected root object type";
        case FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING:
            return "resourceLogs missing";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE:
            return "unexpected resourceLogs type";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_ENTRY_TYPE:
            return "unexpected resourceLogs entry type";
        case FLB_OTEL_LOGS_ERR_SCOPELOGS_MISSING:
            return "scopeLogs missing";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE:
            return "unexpected scopeLogs type";
        case FLB_OTEL_LOGS_ERR_GROUP_METADATA:
            return "could not set group content metadata";
        case FLB_OTEL_LOGS_ERR_SCOPE_METADATA:
            return "could not set scope content metadata";
        case FLB_OTEL_LOGS_ERR_SCOPE_KVLIST:
            return "could not set scope key/value list";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE:
            return "unexpected logRecords entry type";
        case FLB_OTEL_LOGS_ERR_MISSING_TIMESTAMP:
            return "missing timestamp";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE:
            return "unexpected timestamp type";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE:
            return "unexpected attributes type";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE:
            return "unexpected body type";
        case FLB_OTEL_LOGS_ERR_MISSING_LOGRECORDS:
            return "missing logRecords";
        case FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE:
            return "unexpected logRecords type";
        case FLB_OTEL_LOGS_ERR_ENCODER_FAILURE:
            return "log event encoder failure";
        case FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE:
            return "failed to append body";
        default:
            return "unknown error";
    }
}

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

    result = flb_otel_utils_json_payload_get_wrapped_value(object,
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


static int process_json_payload_log_records_entry(
    struct flb_log_event_encoder *encoder,
    msgpack_object *log_records_object,
    int *error_status,
    const char *logs_metadata_key,
    size_t logs_metadata_key_len,
    const char *logs_body_key)
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

    if (error_status) {
        *error_status = 0;
    }

    if (log_records_object->type != MSGPACK_OBJECT_MAP) {
        if (error_status) *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE;
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE;
    }

    log_records_entry = &log_records_object->via.map;

    /* Only check camelCase keys */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "timeUnixNano", 0, FLB_TRUE);
    if (result == -1) {
        /* fallback to observedTimeUnixNano if timeUnixNano is missing */
        result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "observedTimeUnixNano", 0, FLB_TRUE);
    }

    if (result == -1) {
        if (error_status) *error_status = FLB_OTEL_LOGS_ERR_MISSING_TIMESTAMP;
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
            if (error_status) *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
            return -FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
        }

        flb_time_from_uint64(&timestamp, timestamp_uint64);
    }

    /* observedTimeUnixNano (only camelCase) */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "observedTimeUnixNano", 0, FLB_TRUE);
    if (result >= 0) {
        observed_time_unix_nano = &log_records_entry->ptr[result].val;
    }

    /* severityNumber */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "severityNumber", 0, FLB_TRUE);
    if (result >= 0) {
        severity_number = &log_records_entry->ptr[result].val;
    }

    /* severityText */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "severityText", 0, FLB_TRUE);
    if (result >= 0) {
        severity_text = &log_records_entry->ptr[result].val;
    }

    /* attributes */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "attributes", 0, FLB_TRUE);
    if (result == -1) {
        metadata_object = NULL;
    }
    else {
        if (log_records_entry->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
            if (error_status) *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
            return -FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
        }
        metadata_object = &log_records_entry->ptr[result].val;
    }

    /* traceId */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "traceId", 0, FLB_TRUE);
    if (result >= 0) {
        trace_id = &log_records_entry->ptr[result].val;
    }

    /* spanId */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "spanId", 0, FLB_TRUE);
    if (result >= 0) {
        span_id = &log_records_entry->ptr[result].val;
    }

    /* body */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "body", 0, FLB_TRUE);
    if (result == -1) {
        body_object = NULL;
    }
    else {
        if (log_records_entry->ptr[result].val.type != MSGPACK_OBJECT_MAP) {
            if (error_status) *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE;
            return -FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE;
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
        flb_log_event_encoder_append_string(encoder,
                                            FLB_LOG_EVENT_METADATA,
                                            (char *) logs_metadata_key,
                                            logs_metadata_key_len);
        flb_log_event_encoder_begin_map(encoder, FLB_LOG_EVENT_METADATA);

        if (observed_time_unix_nano != NULL && observed_time_unix_nano->type == MSGPACK_OBJECT_STR) {
            memset(timestamp_str, 0, sizeof(timestamp_str));
            if (observed_time_unix_nano->via.str.size < sizeof(timestamp_str)) {
                strncpy(timestamp_str,
                        observed_time_unix_nano->via.str.ptr,
                        observed_time_unix_nano->via.str.size);
            }
            else {
                strncpy(timestamp_str,
                        observed_time_unix_nano->via.str.ptr,
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
            result = flb_otel_utils_json_payload_append_converted_kvlist(encoder, FLB_LOG_EVENT_METADATA, metadata_object);
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
        result = flb_otel_utils_json_payload_get_wrapped_value(body_object, NULL, &body_type);

        if (result != 0 ||
            (logs_body_key == NULL && body_type == MSGPACK_OBJECT_MAP)) {
            flb_log_event_encoder_dynamic_field_reset(&encoder->body);
        }
        else {
            const char *body_key = logs_body_key ? logs_body_key : "log";
            flb_log_event_encoder_append_cstring(
                                                encoder,
                                                FLB_LOG_EVENT_BODY,
                                                (char *) body_key);
        }

        result = json_payload_append_converted_value(encoder,
                                                                    FLB_LOG_EVENT_BODY,
                                                                    body_object);
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            if (error_status) *error_status = FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE;
            flb_log_event_encoder_rollback_record(encoder);
            return -FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE;
        }
    }

    result = flb_log_event_encoder_dynamic_field_flush(&encoder->body);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(encoder);
    }
    else {
        if (error_status) *error_status = FLB_OTEL_LOGS_ERR_ENCODER_FAILURE;
        flb_log_event_encoder_rollback_record(encoder);
        return -FLB_OTEL_LOGS_ERR_ENCODER_FAILURE;
    }

    return result;
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

static int process_json_payload_scope_logs_entry(
        struct flb_log_event_encoder *encoder,
        msgpack_object *scope_logs_object,
        int *error_status)
{
    msgpack_object_map   *scope_logs_entry;
    msgpack_object_array *log_records;
    int entry_status;
    int                   result;
    size_t                index;

    if (error_status) {
        *error_status = 0;
    }

    if (scope_logs_object->type != MSGPACK_OBJECT_MAP) {
        if (error_status) *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
    }

    scope_logs_entry = &scope_logs_object->via.map;

    result = flb_otel_utils_find_map_entry_by_key(scope_logs_entry, "logRecords", 0, FLB_TRUE);

    if (result == -1) {
        if (error_status) *error_status = FLB_OTEL_LOGS_ERR_MISSING_LOGRECORDS;
        return -FLB_OTEL_LOGS_ERR_MISSING_LOGRECORDS;
    }

    if (scope_logs_entry->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        if (error_status) *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE;
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE;
    }

    log_records = &scope_logs_entry->ptr[result].val.via.array;

    result = 0;

    for (index = 0 ; index < log_records->size ; index++) {
        entry_status = 0;
        result = process_json_payload_log_records_entry(
                    encoder,
                    &log_records->ptr[index],
                    &entry_status,
                    FLB_OTEL_LOGS_METADATA_KEY,
                    sizeof(FLB_OTEL_LOGS_METADATA_KEY) - 1,
                    /*
                      * This last parameter used to be for logs_body_key inside
                      * in_opentelemetry, however it seems not being used, passing
                      * NULL for now.
                      */
                    NULL);
        if (result < 0 && error_status) {
            *error_status = entry_status;
            return result;
        }
    }

    return result;
}

static int process_json_payload_resource_logs_entry (
    struct flb_log_event_encoder *encoder,
    size_t resource_logs_index,
    msgpack_object *resource_logs_object,
    int *error_status)
{
    int ret;
    int result = 0;
    size_t index;
    msgpack_object       *obj;
    msgpack_object_map   *resource = NULL;
    msgpack_object       *resource_attr = NULL;
    msgpack_object_map   *resource_logs_entry = NULL;
    msgpack_object       *resource_schema_url = NULL;
    msgpack_object       *scope = NULL;
    msgpack_object_array *scope_logs;
    msgpack_object       *scope_schema_url = NULL;

    if (error_status) {
        *error_status = 0;
    }

    if (resource_logs_object->type != MSGPACK_OBJECT_MAP) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_ENTRY_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_ENTRY_TYPE;
    }

    /* get 'resource' and resource['attributes'] */
    result = flb_otel_utils_find_map_entry_by_key(&resource_logs_object->via.map, "resource", 0, FLB_TRUE);
    if (result >= 0) {
        obj = &resource_logs_object->via.map.ptr[result].val;
        if (obj->type == MSGPACK_OBJECT_MAP) {
            resource = &obj->via.map;

            /* attributes */
            result = flb_otel_utils_find_map_entry_by_key(resource, "attributes", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &resource->ptr[result].val;
                if (obj->type == MSGPACK_OBJECT_ARRAY) {
                    resource_attr = &resource->ptr[result].val;
                }
            }
        }
    }

    resource_logs_entry = &resource_logs_object->via.map;

    /* schemaUrl */
    result = flb_otel_utils_find_map_entry_by_key(resource_logs_entry, "schemaUrl", 0, FLB_TRUE);
    if (result >= 0) {
        obj = &resource_logs_entry->ptr[result].val;
        if (obj->type == MSGPACK_OBJECT_STR) {
            resource_schema_url = &resource_logs_entry->ptr[result].val;
        }
    }

    /* scopeLogs */
    result = flb_otel_utils_find_map_entry_by_key(resource_logs_entry, "scopeLogs", 0, FLB_TRUE);
    if (result == -1) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_SCOPELOGS_MISSING;
        }
        return -FLB_OTEL_LOGS_ERR_SCOPELOGS_MISSING;
    }

    if (resource_logs_entry->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
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
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_GROUP_METADATA;
            }
            return -FLB_OTEL_LOGS_ERR_GROUP_METADATA;
        }

        /* Resource key */
        flb_log_event_encoder_append_body_string(encoder, "resource", 8);

        /* start resource value (map) */
        flb_log_event_encoder_body_begin_map(encoder);

        /* Check if we have OTel resource attributes */
        if (resource_attr) {
            flb_log_event_encoder_append_body_string(encoder, "attributes", 10);
            result = flb_otel_utils_json_payload_append_converted_kvlist(encoder,
                                                                         FLB_LOG_EVENT_BODY,
                                                                         resource_attr);
        }

        /* resource dropped_attributers_count */
        if (resource) {
            result = flb_otel_utils_find_map_entry_by_key(resource, "droppedAttributesCount", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &resource->ptr[result].val;
                flb_log_event_encoder_append_body_values(encoder,
                                                        FLB_LOG_EVENT_CSTRING_VALUE("dropped_attributes_count"),
                                                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(obj));
            }
        }

        if (resource_schema_url) {
            flb_log_event_encoder_append_body_values(encoder,
                                                    FLB_LOG_EVENT_CSTRING_VALUE("schema_url"),
                                                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(resource_schema_url));
        }

        /* close resource map */
        flb_log_event_encoder_body_commit_map(encoder);

        /* scope schemaUrl */
        result = flb_otel_utils_find_map_entry_by_key(&scope_logs->ptr[index].via.map, "schemaUrl", 0, FLB_TRUE);
        if (result >= 0) {
            obj = &scope_logs->ptr[index].via.map.ptr[result].val;
            if (obj->type == MSGPACK_OBJECT_STR) {
                scope_schema_url = &scope_logs->ptr[index].via.map.ptr[result].val;
            }
        }

        /* scope metadata */
        scope = NULL;
        obj = &scope_logs->ptr[index];
        if (obj->type == MSGPACK_OBJECT_MAP) {
            result = flb_otel_utils_find_map_entry_by_key(&obj->via.map, "scope", 0, FLB_TRUE);
            if (result >= 0) {
                if (obj->via.map.ptr[result].val.type == MSGPACK_OBJECT_MAP) {
                    scope = &scope_logs->ptr[index].via.map.ptr[result].val;
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
            result = flb_otel_utils_find_map_entry_by_key(&scope->via.map, "name", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &scope->via.map.ptr[result].val;
                if (obj->type == MSGPACK_OBJECT_STR) {
                    flb_log_event_encoder_append_body_values(encoder,
                                                             FLB_LOG_EVENT_CSTRING_VALUE("name"),
                                                             FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(obj));
                }
            }

            /* scope version */
            result = flb_otel_utils_find_map_entry_by_key(&scope->via.map, "version", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &scope->via.map.ptr[result].val;
                if (obj->type == MSGPACK_OBJECT_STR) {
                    flb_log_event_encoder_append_body_values(encoder,
                                                            FLB_LOG_EVENT_CSTRING_VALUE("version"),
                                                            FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(obj));
                }
            }

            /* scope attributes */
            result = flb_otel_utils_find_map_entry_by_key(&scope->via.map, "attributes", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &scope->via.map.ptr[result].val;
                if (obj->type == MSGPACK_OBJECT_ARRAY) {
                    flb_log_event_encoder_append_body_string(encoder, "attributes", 10);
                    result = flb_otel_utils_json_payload_append_converted_kvlist(encoder,
                                                                                FLB_LOG_EVENT_BODY,
                                                                                obj);
                    if (result != 0) {
                        if (error_status) {
                            *error_status = FLB_OTEL_LOGS_ERR_SCOPE_KVLIST;
                        }
                        return -FLB_OTEL_LOGS_ERR_SCOPE_KVLIST;
                    }
                }
            }

            /* scope schemaUrl */
            if (scope_schema_url) {
                flb_log_event_encoder_append_body_values(encoder,
                                                        FLB_LOG_EVENT_CSTRING_VALUE("schema_url"),
                                                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(scope_schema_url));
            }

            flb_log_event_encoder_commit_map(encoder, FLB_LOG_EVENT_BODY);
        }

        flb_log_event_encoder_commit_map(encoder, FLB_LOG_EVENT_BODY);

        flb_log_event_encoder_group_header_end(encoder);

        result = process_json_payload_scope_logs_entry(
                                                      encoder,
                                                      &scope_logs->ptr[index],
                                                      error_status);
        if (result < 0) {
            /* error_status should already be set by callee */
            flb_log_event_encoder_group_end(encoder);
            return result;
        }
        flb_log_event_encoder_group_end(encoder);
    }

    return result;
}

static int process_json_payload_root(struct flb_log_event_encoder *encoder,
                                     msgpack_object *root_object,
                                     int *error_status)
{
    msgpack_object_array *resource_logs;
    int                   result;
    size_t                index;
    msgpack_object_map   *root;

    if (error_status) {
        *error_status = 0;
    }

    if (root_object->type != MSGPACK_OBJECT_MAP) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE;
    }

    root = &root_object->via.map;
    result = flb_otel_utils_find_map_entry_by_key(root, "resourceLogs", 0, FLB_TRUE);

    if (result == -1) {
        result = flb_otel_utils_find_map_entry_by_key(root, "resource_logs", 0, FLB_TRUE);
        if (result == -1) {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING;
            }
            return -FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING;
        }
    }

    if (root->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE;
    }

    resource_logs = &root->ptr[result].val.via.array;

    result = 0;
    for (index = 0 ; index < resource_logs->size ; index++) {
        result = process_json_payload_resource_logs_entry(
                    encoder,
                    index,
                    &resource_logs->ptr[index],
                    error_status);
    }

    return result;
}

/*
 * Process the OTLP-JSON payload and convert it to msgpack
 * ---------------------------------------------------
 */
int flb_opentelemetry_logs_json_to_msgpack(struct flb_log_event_encoder *encoder,
                                           const char *body, size_t len,
                                           int *error_status)
{
    int              result;
    int              root_type;
    int              release_encoder = FLB_FALSE;
    size_t           msgpack_body_length;
    char            *msgpack_body;
    msgpack_unpacked unpacked_root;
    size_t           offset = 0;
    struct flb_log_event_encoder *local_log_encoder;

    /* If no log encoder is provided, just instance a new one*/
    if (encoder == NULL) {
        local_log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
        if (local_log_encoder == NULL) {
            return -1;
        }
        release_encoder = FLB_TRUE;
    }
    else {
        local_log_encoder = encoder;
        release_encoder = FLB_FALSE;
    }

    /* Convert JSON to messagepack */
    result = flb_pack_json(body, len, &msgpack_body, &msgpack_body_length,
                           &root_type, NULL);

    if (result != 0) {
        if (release_encoder) {
            flb_log_event_encoder_destroy(local_log_encoder);
        }
        return -1;
    }

    offset = 0;
    msgpack_unpacked_init(&unpacked_root);
    result = msgpack_unpack_next(&unpacked_root,
                                 msgpack_body,
                                 msgpack_body_length,
                                 &offset);
    if (result != MSGPACK_UNPACK_SUCCESS) {
        if (release_encoder) {
            flb_log_event_encoder_destroy(local_log_encoder);
        }
        msgpack_unpacked_destroy(&unpacked_root);
        flb_free(msgpack_body);
        return -1;
    }

    /* decode OTLP/JSON as raw messagepack and do the proper encoding (groups, name-to-lowercase, etc) */
    result = process_json_payload_root(local_log_encoder, &unpacked_root.data, error_status);

    /* clean up */
    if (release_encoder) {
        flb_log_event_encoder_destroy(local_log_encoder);
    }

    msgpack_unpacked_destroy(&unpacked_root);
    flb_free(msgpack_body);

    return result;
}
