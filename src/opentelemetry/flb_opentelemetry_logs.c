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
#include <fluent-bit/flb_opentelemetry.h>
#include <ctype.h>

#include <fluent-otel-proto/fluent-otel.h>

#define FLB_OTEL_LOGS_METADATA_KEY "otlp"

static int process_json_payload_log_records_entry(
    struct flb_log_event_encoder *encoder,
    msgpack_object *log_records_object,
    const char *logs_metadata_key,
    size_t logs_metadata_key_len,
    const char *logs_body_key,
    int *error_status)
{
    int                 i;
    int                 result;
    int                 body_type;
    unsigned char       tmp_id[32];
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
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE;
    }

    log_records_entry = &log_records_object->via.map;

    /* Only check camelCase keys */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "timeUnixNano", 0, FLB_TRUE);
    if (result == -1) {
        /* fallback to observedTimeUnixNano if timeUnixNano is missing */
        result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "observedTimeUnixNano", 0, FLB_TRUE);
    }

    /* we need a timestamp... */
    if (result == -1) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_MISSING_TIMESTAMP;
        }
        return -FLB_OTEL_LOGS_ERR_MISSING_TIMESTAMP;

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

            /* validate that the string only contains digits */
            for (i = 0; i < strlen(timestamp_str); i++) {
                if (!isdigit((unsigned char) timestamp_str[i])) {
                    if (error_status) {
                        *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
                    }
                    return -FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
                }
            }

            timestamp_uint64 = strtoull(timestamp_str, NULL, 10);
        }
        else {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
            }
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
            /* attributes must be an array per OTLP spec; return error if not */
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
            }
            return -FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
        }
        metadata_object = &log_records_entry->ptr[result].val;
    }

    /* traceId */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "traceId", 0, FLB_TRUE);
    if (result >= 0) {
        trace_id = &log_records_entry->ptr[result].val;
    }

    /* trace_id must be a 32 char hex string */
    if (trace_id != NULL) {
        if (trace_id->type != MSGPACK_OBJECT_STR) {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID;
            }
            return -FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID;
        }

        if (trace_id->via.str.size != 32) {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID;
            }
            return -FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID;
        }

        /* Validate hex format */
        for (i = 0; i < 32; i++) {
            if (!isxdigit(trace_id->via.str.ptr[i])) {
                if (error_status) {
                     *error_status = FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID;
                }
                return -FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID;
            }
        }
    }

    /* spanId */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "spanId", 0, FLB_TRUE);
    if (result >= 0) {
        span_id = &log_records_entry->ptr[result].val;
    }

    if (span_id != NULL) {
        if (span_id->type != MSGPACK_OBJECT_STR) {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID;
            }
            return -FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID;
        }

        if (span_id->via.str.size != 16) {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID;
            }
            return -FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID;
        }

        /* Validate hex format */
        for (i = 0; i < 16; i++) {
            if (!isxdigit(span_id->via.str.ptr[i])) {
                if (error_status) {
                    *error_status = FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID;
                }
                return -FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
            }
        }
    }

    /* body */
    result = flb_otel_utils_find_map_entry_by_key(log_records_entry, "body", 0, FLB_TRUE);
    if (result == -1) {
        body_object = NULL;
    }
    else {
        if (log_records_entry->ptr[result].val.type != MSGPACK_OBJECT_MAP) {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE;
            }
            return -FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE;
        }
        body_object = &log_records_entry->ptr[result].val;
    }

    result = flb_log_event_encoder_begin_record(encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(encoder, &timestamp);
    }

    flb_log_event_encoder_append_metadata_values(encoder,
                                                 FLB_LOG_EVENT_CSTRING_VALUE(FLB_OTEL_LOGS_METADATA_KEY));


    result = flb_log_event_encoder_begin_map(encoder, FLB_LOG_EVENT_METADATA);

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
        for (i = 0; i < strlen(timestamp_str); i++) {
            if (!isdigit((unsigned char) timestamp_str[i])) {
                timestamp_str[0] = '\0';
                break;
            }
        }

        if (strlen(timestamp_str) > 0) {
            timestamp_uint64 = strtoull(timestamp_str, NULL, 10);

            flb_log_event_encoder_append_metadata_values(encoder,
                                                        FLB_LOG_EVENT_STRING_VALUE("observed_timestamp", 18),
                                                        FLB_LOG_EVENT_INT64_VALUE(timestamp_uint64));
        }
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

    if (trace_id != NULL && trace_id->type == MSGPACK_OBJECT_STR && trace_id->via.str.size == 32) {
        flb_otel_utils_hex_to_id(trace_id->via.str.ptr, trace_id->via.str.size, tmp_id, 16);
        flb_log_event_encoder_append_metadata_values(encoder,
                                                        FLB_LOG_EVENT_STRING_VALUE("trace_id", 8),
                                                        FLB_LOG_EVENT_BINARY_VALUE(tmp_id, 16));
    }

    if (span_id != NULL && span_id->type == MSGPACK_OBJECT_STR && span_id->via.str.size == 16) {
        flb_otel_utils_hex_to_id(span_id->via.str.ptr, span_id->via.str.size, tmp_id, 8);
        flb_log_event_encoder_append_metadata_values(encoder,
                                                        FLB_LOG_EVENT_STRING_VALUE("span_id", 7),
                                                        FLB_LOG_EVENT_BINARY_VALUE(tmp_id, 8));
    }

    result = flb_log_event_encoder_commit_map(encoder, FLB_LOG_EVENT_METADATA);

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

        result = flb_otel_utils_json_payload_append_converted_value(encoder,
                                                                    FLB_LOG_EVENT_BODY,
                                                                    body_object);
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            if (error_status) {
                *error_status = FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE;
            }
            flb_log_event_encoder_rollback_record(encoder);
            return -FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE;
        }
    }

    result = flb_log_event_encoder_dynamic_field_flush(&encoder->body);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(encoder);
    }
    else {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_ENCODER_FAILURE;
        }
        flb_log_event_encoder_rollback_record(encoder);
        return -FLB_OTEL_LOGS_ERR_ENCODER_FAILURE;
    }

    return result;
}

static int process_json_payload_scope_logs_entry(
        struct flb_log_event_encoder *encoder,
        msgpack_object *scope_logs_object,
        const char *logs_body_key,
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
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
    }

    scope_logs_entry = &scope_logs_object->via.map;

    result = flb_otel_utils_find_map_entry_by_key(scope_logs_entry, "logRecords", 0, FLB_TRUE);
    if (result == -1) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD;
        }
        return 0;
    }

    if (scope_logs_entry->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE;
    }

    log_records = &scope_logs_entry->ptr[result].val.via.array;

    result = 0;

    for (index = 0 ; index < log_records->size ; index++) {
        entry_status = 0;
        result = process_json_payload_log_records_entry(
                    encoder,
                    &log_records->ptr[index],
                    FLB_OTEL_LOGS_METADATA_KEY,
                    sizeof(FLB_OTEL_LOGS_METADATA_KEY) - 1,
                    logs_body_key,
                    &entry_status);
        if (result < 0 && error_status) {
            *error_status = entry_status;
            return result;
        }
    }

    return result;
}

static int process_json_payload_resource_logs_entry (struct flb_log_event_encoder *encoder,
                                                     size_t resource_logs_index,
                                                     msgpack_object *resource_logs_object,
                                                     const char *logs_body_key,
                                                     int *error_status)
{
    int ret;
    int result = 0;
    size_t index;
    size_t size_before;
    size_t size_after;
    struct flb_log_event_encoder *tmp_encoder;
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
                else {
                    /* resource attributes must be an array per OTLP spec; return error if not */
                    if (error_status) {
                        *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
                    }
                    return -FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
                }
            }
        }
    }
    else {
        /* it's ok to not having resources */
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
    if (scope_logs->size == 0) {
        /* no scope logs, nothing to process */
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD;
        }
        return 0;
    }

    for (index = 0 ; index < scope_logs->size ; index++) {

        /*
         * we use a temporary encoder to hold the group information, if no record entries are added
         * we will discard it.
         **/
        tmp_encoder = flb_log_event_encoder_create(encoder->format);
        flb_log_event_encoder_group_init(tmp_encoder);

        /* pack internal schema */
        ret = flb_log_event_encoder_append_metadata_values(tmp_encoder,
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
            flb_log_event_encoder_destroy(tmp_encoder);
            return -FLB_OTEL_LOGS_ERR_GROUP_METADATA;
        }

        /* Resource key */
        flb_log_event_encoder_append_body_string(tmp_encoder, "resource", 8);

        /* start resource value (map) */
        flb_log_event_encoder_body_begin_map(tmp_encoder);

        /* Check if we have OTel resource attributes */
        if (resource_attr) {
            flb_log_event_encoder_append_body_string(tmp_encoder, "attributes", 10);
            result = flb_otel_utils_json_payload_append_converted_kvlist(tmp_encoder,
                                                                         FLB_LOG_EVENT_BODY,
                                                                         resource_attr);
            if (result < 0) {
                if (error_status) {
                    *error_status = FLB_OTEL_RESOURCE_INVALID_ATTRIBUTE;
                }
                flb_log_event_encoder_destroy(tmp_encoder);
                return -FLB_OTEL_RESOURCE_INVALID_ATTRIBUTE;
            }
        }

        /* resource dropped_attributers_count */
        if (resource) {
            result = flb_otel_utils_find_map_entry_by_key(resource, "droppedAttributesCount", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &resource->ptr[result].val;
                flb_log_event_encoder_append_body_values(tmp_encoder,
                                                        FLB_LOG_EVENT_CSTRING_VALUE("dropped_attributes_count"),
                                                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(obj));
            }
        }

        if (resource_schema_url) {
            flb_log_event_encoder_append_body_values(tmp_encoder,
                                                    FLB_LOG_EVENT_CSTRING_VALUE("schema_url"),
                                                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(resource_schema_url));
        }

        /* close resource map */
        flb_log_event_encoder_body_commit_map(tmp_encoder);

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
            flb_log_event_encoder_append_body_string(tmp_encoder, "scope", 5);

            /* scope map value */
            flb_log_event_encoder_body_begin_map(tmp_encoder);

            /* scope name */
            result = flb_otel_utils_find_map_entry_by_key(&scope->via.map, "name", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &scope->via.map.ptr[result].val;
                if (obj->type == MSGPACK_OBJECT_STR) {
                    flb_log_event_encoder_append_body_values(tmp_encoder,
                                                             FLB_LOG_EVENT_CSTRING_VALUE("name"),
                                                             FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(obj));
                }
            }

            /* scope version */
            result = flb_otel_utils_find_map_entry_by_key(&scope->via.map, "version", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &scope->via.map.ptr[result].val;
                if (obj->type == MSGPACK_OBJECT_STR) {
                    flb_log_event_encoder_append_body_values(tmp_encoder,
                                                            FLB_LOG_EVENT_CSTRING_VALUE("version"),
                                                            FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(obj));
                }
            }

            /* scope attributes */
            result = flb_otel_utils_find_map_entry_by_key(&scope->via.map, "attributes", 0, FLB_TRUE);
            if (result >= 0) {
                obj = &scope->via.map.ptr[result].val;
                if (obj->type == MSGPACK_OBJECT_ARRAY) {
                    flb_log_event_encoder_append_body_string(tmp_encoder, "attributes", 10);
                    result = flb_otel_utils_json_payload_append_converted_kvlist(tmp_encoder,
                                                                                FLB_LOG_EVENT_BODY,
                                                                                obj);
                    if (result != 0) {
                        if (error_status) {
                            *error_status = FLB_OTEL_LOGS_ERR_SCOPE_KVLIST;
                        }
                        flb_log_event_encoder_destroy(tmp_encoder);
                        return -FLB_OTEL_LOGS_ERR_SCOPE_KVLIST;
                    }
                }
                else {
                    /* scope attributes must be an array per OTLP spec; return error if not */
                    if (error_status) {
                        *error_status = FLB_OTEL_LOGS_ERR_SCOPE_KVLIST;
                    }
                    flb_log_event_encoder_destroy(tmp_encoder);
                    return -FLB_OTEL_LOGS_ERR_SCOPE_KVLIST;
                }
            }

            /* scope schemaUrl */
            if (scope_schema_url) {
                flb_log_event_encoder_append_body_values(tmp_encoder,
                                                        FLB_LOG_EVENT_CSTRING_VALUE("schema_url"),
                                                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(scope_schema_url));
            }

            /* close scope map */
            flb_log_event_encoder_commit_map(tmp_encoder, FLB_LOG_EVENT_BODY);
        }
        flb_log_event_encoder_group_header_end(tmp_encoder);

        /* before processing the scope logs, grab the number of bytes written */
        size_before = tmp_encoder->buffer.size;

        /* Process the scope logs entry */
        result = process_json_payload_scope_logs_entry(
                                                      tmp_encoder,
                                                      &scope_logs->ptr[index],
                                                      logs_body_key,
                                                      error_status);
        size_after = tmp_encoder->buffer.size;

        if (result < 0) {
            flb_log_event_encoder_destroy(tmp_encoder);
            return result;
        }

        /*
         * If at least one log was valid and registered, finalize the group and copy the content to
         * the main encoder
         */
        if (size_after > size_before) {
            flb_log_event_encoder_group_end(tmp_encoder);

            /* Append the temporary encoder output to the main encoder */
            msgpack_sbuffer_write(&encoder->buffer,
                                  tmp_encoder->output_buffer,
                                  tmp_encoder->output_length);

            encoder->output_buffer = encoder->buffer.data;
            encoder->output_length = encoder->buffer.size;
        }

        flb_log_event_encoder_destroy(tmp_encoder);
    }

    return result;
}

static int process_json_payload_root(struct flb_log_event_encoder *encoder,
                                     msgpack_object *root_object,
                                     const char *logs_body_key,
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
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING;
        }
        return -FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING;
    }

    if (root->ptr[result].val.type != MSGPACK_OBJECT_ARRAY) {
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE;
    }

    resource_logs = &root->ptr[result].val.via.array;

    if (resource_logs->size == 0) {
        if (error_status) {
            /* not an error, but we need to tell the caller why no data was ingested */
            *error_status = FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD;
        }
        return 0; /* no resource logs, nothing to process */
    }

    result = 0;
    for (index = 0 ; index < resource_logs->size ; index++) {
        result = process_json_payload_resource_logs_entry(
                    encoder,
                    index,
                    &resource_logs->ptr[index],
                    logs_body_key,
                    error_status);
        if (result < 0) {
            /* error_status should already be set by callee */
            return result;
        }
    }

    return result;
}

/*
 * Process the OTLP-JSON payload and convert it to msgpack
 * ---------------------------------------------------
 */
/*
 * The original implementation allows the caller to pass a NULL encoder,
 * in which case the function creates a local encoder, uses it, and destroys it before returning.
 * However, since the encoder is not returned to the caller, the caller cannot access the encoded data.
 * This makes the "encoder == NULL" case only useful for scenarios where the caller is interested
 * solely in validation or error checking, not in retrieving the encoded output.
 *
 * In practice, all meaningful use cases require the caller to access the encoded data,
 * so a valid encoder should always be provided. If the function is called with encoder == NULL,
 * it cannot return the encoded result, making this usage of limited value.
 *
 * Therefore, we simplify the function to always require a valid encoder.
 * If encoder is NULL, we return an error immediately.
 */
int flb_opentelemetry_logs_json_to_msgpack(struct flb_log_event_encoder *encoder,
                                           const char *body, size_t len,
                                           const char *logs_body_key,
                                           int *error_status)
{
    int              result;
    int              root_type;
    size_t           msgpack_body_length;
    char            *msgpack_body;
    msgpack_unpacked unpacked_root;
    size_t           offset = 0;
    struct flb_log_event_encoder local_log_encoder;

    if (encoder == NULL) {
        return -1;
    }

    /* Convert JSON to messagepack */
    result = flb_pack_json(body, len, &msgpack_body, &msgpack_body_length,
                           &root_type, NULL);

    if (result != 0) {
        return -1;
    }

    /* Initialize the local encoder, we use this one in case an exception happens */
    result = flb_log_event_encoder_init(&local_log_encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        flb_free(msgpack_body);
        return -1;
    }

    offset = 0;
    msgpack_unpacked_init(&unpacked_root);
    result = msgpack_unpack_next(&unpacked_root,
                                 msgpack_body,
                                 msgpack_body_length,
                                 &offset);
    if (result != MSGPACK_UNPACK_SUCCESS) {
        flb_log_event_encoder_destroy(&local_log_encoder);
        msgpack_unpacked_destroy(&unpacked_root);
        flb_free(msgpack_body);
        if (error_status) {
            *error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE;
        }
        return -FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE;
    }

    /* decode OTLP/JSON as raw messagepack and do the proper encoding (groups, name-to-lowercase, etc) */
    result = process_json_payload_root(&local_log_encoder,
                                       &unpacked_root.data,
                                       logs_body_key,
                                       error_status);

    if (result < 0) {
        flb_log_event_encoder_destroy(&local_log_encoder);
        msgpack_unpacked_destroy(&unpacked_root);
        flb_free(msgpack_body);
        return result;
    }

    /* clean up */
    msgpack_unpacked_destroy(&unpacked_root);
    flb_free(msgpack_body);

    /* copy local buffer into caller encoder buffer */
    if (local_log_encoder.output_length > 0) {
        msgpack_sbuffer_write(&encoder->buffer,
                            local_log_encoder.output_buffer,
                            local_log_encoder.output_length);
        encoder->output_buffer = encoder->buffer.data;
        encoder->output_length = encoder->buffer.size;
    }

    flb_log_event_encoder_destroy(&local_log_encoder);

    return result;
}
