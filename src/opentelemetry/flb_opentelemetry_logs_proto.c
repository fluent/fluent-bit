/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-otel-proto/fluent-otel.h>

#include <cfl/cfl_arena.h>

#include <limits.h>

/*
 * Small requests use protobuf-c's default allocator to avoid reserving an
 * arena chunk. Realistic batched requests use the arena to amortize the large
 * number of short-lived allocations performed by protobuf-c.
 */
#define OTEL_PROTOBUF_ARENA_MIN_PAYLOAD_SIZE 8192
#define OTEL_PROTOBUF_ARENA_INITIAL_CHUNK_SIZE 4096
#define OTEL_PROTOBUF_ARENA_MAX_CHUNK_SIZE 65536

static void *protobuf_arena_chunk_malloc(void *context, size_t size)
{
    (void) context;

    return flb_malloc(size);
}
static void protobuf_arena_chunk_free(void *context, void *pointer)
{
    (void) context;

    flb_free(pointer);
}

static void *protobuf_arena_alloc(void *allocator_data, size_t size)
{
    struct cfl_arena *arena;

    arena = allocator_data;
    if (size == 0) {
        size = 1;
    }

    return cfl_arena_malloc(arena, size);
}

static void protobuf_arena_free(void *allocator_data, void *pointer)
{
    (void) allocator_data;
    (void) pointer;
}

static struct cfl_arena *protobuf_arena_create(void)
{
    struct cfl_arena_options options;

    cfl_arena_options_init(&options);
    options.chunk_size = OTEL_PROTOBUF_ARENA_INITIAL_CHUNK_SIZE;
    options.maximum_chunk_size = OTEL_PROTOBUF_ARENA_MAX_CHUNK_SIZE;
    options.malloc_fn = protobuf_arena_chunk_malloc;
    options.free_fn = protobuf_arena_chunk_free;

    return cfl_arena_create_with_options(&options);
}

static Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *
protobuf_logs_unpack(ProtobufCAllocator *allocator, size_t size, const uint8_t *data)
{
    if (flb_opentelemetry_protobuf_validate(
            &opentelemetry__proto__collector__logs__v1__export_logs_service_request__descriptor,
            data, size) != 0) {
        return NULL;
    }
    return opentelemetry__proto__collector__logs__v1__export_logs_service_request__unpack(
        allocator, size, data);
}

static void protobuf_logs_free(
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *logs,
    ProtobufCAllocator *allocator)
{
    /*
     * Every allocation of an arena backed request is released with the arena,
     * walking the message tree here would only call the no-op free callback.
     */
    if (allocator != NULL && allocator->free == protobuf_arena_free) {
        return;
    }

    opentelemetry__proto__collector__logs__v1__export_logs_service_request__free_unpacked(
        logs, allocator);
}

/* Unpack a logs request, using an arena for realistic batched payloads */
static Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *
protobuf_logs_decode(uint8_t *in_buf, size_t in_size,
                     struct cfl_arena **protobuf_arena,
                     ProtobufCAllocator *arena_allocator,
                     ProtobufCAllocator **protobuf_allocator)
{
    *protobuf_arena = NULL;
    *protobuf_allocator = NULL;

    if (in_size >= OTEL_PROTOBUF_ARENA_MIN_PAYLOAD_SIZE) {
        *protobuf_arena = protobuf_arena_create();
        if (*protobuf_arena != NULL) {
            arena_allocator->alloc = protobuf_arena_alloc;
            arena_allocator->free = protobuf_arena_free;
            arena_allocator->allocator_data = *protobuf_arena;
            *protobuf_allocator = arena_allocator;
        }
    }

    return protobuf_logs_unpack(*protobuf_allocator, in_size, in_buf);
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

static int otel_pack_int(msgpack_packer *mp_pck, int64_t val)
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

    if (body == NULL) {
        msgpack_pack_nil(mp_pck);
        return 0;
    }

    switch(body->value_case){
        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE:
            result = otel_pack_string(mp_pck, body->string_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX:
            /* Profiling-only string dictionary reference: ignore in logs. */
            result = msgpack_pack_nil(mp_pck);
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

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE__NOT_SET:
            /* treat an unset value as null */
            result = msgpack_pack_nil(mp_pck);
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
static int otel_pack_v1_metadata(
                                 const struct flb_opentelemetry_logs_decode_options *options,
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

    len = strlen(options->metadata_key);

    /* otlp key start */
    flb_mp_map_header_append(&otlp_mh);

    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, options->metadata_key, len);

    flb_mp_map_header_init(&mh, mp_pck);

    if (log_record->observed_time_unix_nano != 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 18);
        msgpack_pack_str_body(mp_pck, "observed_timestamp", 18);
        msgpack_pack_uint64(mp_pck, log_record->observed_time_unix_nano);
    }

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

    if (log_record->dropped_attributes_count > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 24);
        msgpack_pack_str_body(mp_pck, "dropped_attributes_count", 24);
        msgpack_pack_uint64(mp_pck, log_record->dropped_attributes_count);
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

    if (log_record->event_name != NULL && strlen(log_record->event_name) > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "event_name", 10);
        msgpack_pack_str(mp_pck, strlen(log_record->event_name));
        msgpack_pack_str_body(mp_pck, log_record->event_name, strlen(log_record->event_name));
    }

    flb_mp_map_header_end(&mh);

    /* otlp key end */
    flb_mp_map_header_end(&otlp_mh);

    return 0;
}

int flb_opentelemetry_logs_protobuf_to_msgpack(
        struct flb_log_event_encoder *encoder,
        const void *payload, size_t payload_size,
        const struct flb_opentelemetry_logs_decode_options *options,
        size_t *record_count)
{
    int ret = 0;
    int len;
    int resource_logs_index;
    int scope_log_index;
    int log_record_index;
    char *logs_body_key;
    int scope_has_schema_url;
    struct cfl_arena *protobuf_arena;
    struct flb_mp_map_header mh;
    struct flb_mp_map_header mh_tmp;
    struct flb_time tm;
    ProtobufCAllocator arena_allocator;
    ProtobufCAllocator *protobuf_allocator;

    msgpack_packer *mp_pck;
    msgpack_packer *mp_pck_meta;

    /* OTel proto suff */
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *input_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **scope_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;
    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope;

    Opentelemetry__Proto__Logs__V1__ResourceLogs **resource_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__LogRecord **log_records;
    Opentelemetry__Proto__Resource__V1__Resource *resource;

    mp_pck = &encoder->body.packer;
    mp_pck_meta = &encoder->metadata.packer;
    *record_count = 0;

    /* unpack logs from protobuf payload */
    if (encoder == NULL || options == NULL || options->metadata_key == NULL ||
        record_count == NULL || (payload == NULL && payload_size != 0)) {
        return -1;
    }

    input_logs = protobuf_logs_decode((uint8_t *) payload, payload_size, &protobuf_arena,
                                      &arena_allocator, &protobuf_allocator);
    if (input_logs == NULL) {
        flb_warn("[opentelemetry] failed to unpack protobuf logs payload");
        ret = -1;
        goto binary_payload_to_msgpack_end;
    }

    resource_logs = input_logs->resource_logs;
    if (input_logs->n_resource_logs == 0) {
        ret = 0;
        goto binary_payload_to_msgpack_end;
    }

    if (resource_logs == NULL) {
        flb_warn("[opentelemetry] no resource logs found");
        ret = -1;
        goto binary_payload_to_msgpack_end;
    }

    for (resource_logs_index = 0; resource_logs_index < input_logs->n_resource_logs; resource_logs_index++) {
        resource_log = resource_logs[resource_logs_index];
        if (resource_log == NULL) {
            flb_warn("[opentelemetry] null resource logs entry found");
            ret = -1;
            goto binary_payload_to_msgpack_end;
        }

        resource = resource_log->resource;
        scope_logs = resource_log->scope_logs;

        if (resource_log->n_scope_logs > 0 && scope_logs == NULL) {
            flb_warn("[opentelemetry] no scope logs found");
            ret = -1;
            goto binary_payload_to_msgpack_end;
        }

        for (scope_log_index = 0; scope_log_index < resource_log->n_scope_logs; scope_log_index++) {
            scope_log = scope_logs[scope_log_index];
            if (scope_log == NULL) {
                flb_warn("[opentelemetry] null scope logs entry found");
                ret = -1;
                goto binary_payload_to_msgpack_end;
            }

            log_records = scope_log->log_records;

            if (scope_log->n_log_records == 0) {
                continue;
            }

            if (log_records == NULL) {
                flb_warn("[opentelemetry] no log records found");
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


            ret = flb_log_event_encoder_dynamic_field_reset(&encoder->body);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_error("[opentelemetry] failed to reset log event body: %s",
                          flb_log_event_encoder_get_error_description(ret));
                goto binary_payload_to_msgpack_end;
            }

            flb_mp_map_header_init(&mh, mp_pck);

            /* Resource */
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(mp_pck, 8);
            msgpack_pack_str_body(mp_pck, "resource", 8);

            flb_mp_map_header_init(&mh_tmp, mp_pck);
            if (resource) {
                /* look for OTel resource attributes */
                if (resource->n_attributes > 0 && resource->attributes) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 10);
                    msgpack_pack_str_body(mp_pck, "attributes", 10);

                    ret = otel_pack_kvarray(mp_pck,
                                            resource->attributes,
                                            resource->n_attributes);
                    if (ret != 0) {
                        goto binary_payload_to_msgpack_end;
                    }
                }

                if (resource->dropped_attributes_count > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 24);
                    msgpack_pack_str_body(mp_pck, "dropped_attributes_count", 24);
                    msgpack_pack_uint64(mp_pck, resource->dropped_attributes_count);
                }

                if (resource_log->schema_url) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 10);
                    msgpack_pack_str_body(mp_pck, "schema_url", 10);

                    len = strlen(resource_log->schema_url);
                    msgpack_pack_str(mp_pck, len);
                    msgpack_pack_str_body(mp_pck, resource_log->schema_url, len);
                }
            }
            flb_mp_map_header_end(&mh_tmp);

            /* scope */
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(mp_pck, 5);
            msgpack_pack_str_body(mp_pck, "scope", 5);

            /* Scope */
            scope = scope_log->scope;
            scope_has_schema_url = FLB_FALSE;

            if (scope_log->schema_url && strlen(scope_log->schema_url) > 0) {
                scope_has_schema_url = FLB_TRUE;
            }

            if (scope && (scope->name || scope->version ||
                          scope->n_attributes > 0 || scope->dropped_attributes_count > 0 ||
                          scope_has_schema_url == FLB_TRUE)) {
                flb_mp_map_header_init(&mh_tmp, mp_pck);

                if (scope_has_schema_url == FLB_TRUE) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 10);
                    msgpack_pack_str_body(mp_pck, "schema_url", 10);

                    len = strlen(scope_log->schema_url);
                    msgpack_pack_str(mp_pck, len);
                    msgpack_pack_str_body(mp_pck, scope_log->schema_url, len);
                }

                if (scope->name && strlen(scope->name) > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 4);
                    msgpack_pack_str_body(mp_pck, "name", 4);

                    len = strlen(scope->name);
                    msgpack_pack_str(mp_pck, len);
                    msgpack_pack_str_body(mp_pck, scope->name, len);
                }
                if (scope->version && strlen(scope->version) > 0) {
                    flb_mp_map_header_append(&mh_tmp);

                    msgpack_pack_str(mp_pck, 7);
                    msgpack_pack_str_body(mp_pck, "version", 7);

                    len = strlen(scope->version);
                    msgpack_pack_str(mp_pck, len);
                    msgpack_pack_str_body(mp_pck, scope->version, len);
                }

                if (scope->n_attributes > 0 && scope->attributes) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 10);
                    msgpack_pack_str_body(mp_pck, "attributes", 10);
                    ret = otel_pack_kvarray(mp_pck,
                                            scope->attributes,
                                            scope->n_attributes);
                    if (ret != 0) {
                        goto binary_payload_to_msgpack_end;
                    }
                }

                if (scope->dropped_attributes_count > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 24);
                    msgpack_pack_str_body(mp_pck, "dropped_attributes_count", 24);
                    msgpack_pack_uint64(mp_pck, scope->dropped_attributes_count);
                }

                flb_mp_map_header_end(&mh_tmp);
            }
            else {
                flb_mp_map_header_init(&mh_tmp, mp_pck);

                if (scope_has_schema_url == FLB_TRUE) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(mp_pck, 10);
                    msgpack_pack_str_body(mp_pck, "schema_url", 10);

                    len = strlen(scope_log->schema_url);
                    msgpack_pack_str(mp_pck, len);
                    msgpack_pack_str_body(mp_pck, scope_log->schema_url, len);
                }

                flb_mp_map_header_end(&mh_tmp);
            }

            flb_mp_map_header_end(&mh);

            ret = flb_log_event_encoder_dynamic_field_flush(&encoder->body);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_error("[opentelemetry] could not set group content metadata: %s",
                          flb_log_event_encoder_get_error_description(ret));
                goto binary_payload_to_msgpack_end;
            }

            ret = flb_log_event_encoder_group_header_end(encoder);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                goto binary_payload_to_msgpack_end;
            }

            for (log_record_index=0; log_record_index < scope_log->n_log_records; log_record_index++) {
                ret = flb_log_event_encoder_begin_record(encoder);

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    if (log_records[log_record_index]->time_unix_nano > 0) {
                        ret = flb_time_from_uint64(
                                &tm,
                                log_records[log_record_index]->time_unix_nano);
                        if (ret == 0) {
                            ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
                        }
                    }
                    else if (log_records[log_record_index]->observed_time_unix_nano > 0) {
                        ret = flb_time_from_uint64(
                                &tm,
                                log_records[log_record_index]->observed_time_unix_nano);
                        if (ret == 0) {
                            ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
                        }
                    }
                    else {
                        flb_time_get(&tm);
                        ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
                    }
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_dynamic_field_reset(&encoder->metadata);
                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_error("[opentelemetry] failed to reset log event metadata: %s",
                                  flb_log_event_encoder_get_error_description(ret));
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        ret = otel_pack_v1_metadata(options,
                                                    mp_pck_meta,
                                                    log_records[log_record_index],
                                                    resource,
                                                    scope_log->scope);
                    }

                    if (ret != 0) {
                        flb_error("[opentelemetry] failed to convert log record");
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        ret = flb_log_event_encoder_dynamic_field_flush(&encoder->metadata);
                    }
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_dynamic_field_reset(&encoder->body);
                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_error("[opentelemetry] failed to reset log event body: %s",
                                  flb_log_event_encoder_get_error_description(ret));
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else if (options->body_key == NULL &&
                             log_records[log_record_index]->body != NULL &&
                             log_records[log_record_index]->body->value_case ==
                             OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
                        ret = otlp_pack_any_value(
                                mp_pck,
                                log_records[log_record_index]->body);
                    }
                    else {
                        logs_body_key = (char *) options->body_key;
                        if (logs_body_key == NULL) {
                            logs_body_key = "log";
                        }
                        ret = msgpack_pack_map(mp_pck, 1);
                        if (ret == 0) {
                            ret = msgpack_pack_str(mp_pck, strlen(logs_body_key));
                        }
                        if (ret == 0) {
                            ret = msgpack_pack_str_body(mp_pck,
                                                        logs_body_key,
                                                        strlen(logs_body_key));
                        }
                        if (ret == 0) {
                            ret = otlp_pack_any_value(
                                    mp_pck,
                                    log_records[log_record_index]->body);
                        }
                    }

                    if (ret != 0) {
                        flb_error("[opentelemetry] failed to convert log record body");
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        ret = flb_log_event_encoder_dynamic_field_flush(&encoder->body);
                    }
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_commit_record(encoder);
                    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                        (*record_count)++;
                    }
                    else {
                        goto binary_payload_to_msgpack_end;
                    }
                }
                else {
                    flb_error("[opentelemetry] marshalling error");
                    goto binary_payload_to_msgpack_end;
                }
            }

            ret = flb_log_event_encoder_group_end(encoder);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                goto binary_payload_to_msgpack_end;
            }

        }
    }

 binary_payload_to_msgpack_end:
    if (input_logs) {
        protobuf_logs_free(input_logs, protobuf_allocator);
    }
    cfl_arena_destroy(protobuf_arena);

    if (ret != 0) {
        return -1;
    }

    return 0;
}

/*
 * OTLP encoding functions to build the log records as CFL objects
 * ---------------------------------------------------------------
 *
 * When the input processors can take a chunk of CFL records, the protobuf
 * request is converted straight into the records the processors work on,
 * skipping the msgpack buffer they would otherwise decode. The records match
 * what the processors get from the msgpack encoding above: non-negative
 * integers are unsigned values and strings or bytes are borrowed from the
 * unpacked request, which outlives the processing.
 *
 * 'size' is the MessagePack size the msgpack encoding above produces for the
 * same request. It enforces 'logs_max_size' exactly like that path, without
 * building the intermediate MessagePack buffer: metadata and group maps use
 * 32-bit headers, attribute maps, kvlists and the body map compact ones.
 */
#define OTEL_CFL_MAP_HEADER_SIZE 5
#define OTEL_CFL_RECORD_SIZE     12

struct otel_cfl_builder {
    const struct flb_opentelemetry_logs_decode_options *options;
    struct flb_mp_chunk_cobj *chunk;
    struct cfl_arena *arena;
    size_t size;
    size_t limit;
};

static int otel_cfl_account(struct otel_cfl_builder *builder, size_t bytes)
{
    if (bytes > builder->limit || builder->size > builder->limit - bytes) {
        return -1;
    }

    builder->size += bytes;
    return 0;
}

static size_t otel_cfl_uint_size(uint64_t value)
{
    if (value <= 0x7f) {
        return 1;
    }
    if (value <= UINT8_MAX) {
        return 2;
    }
    if (value <= UINT16_MAX) {
        return 3;
    }
    if (value <= UINT32_MAX) {
        return 5;
    }

    return 9;
}

static size_t otel_cfl_int_size(int64_t value)
{
    if (value >= -32) {
        return 1;
    }
    if (value >= INT8_MIN) {
        return 2;
    }
    if (value >= INT16_MIN) {
        return 3;
    }
    if (value >= INT32_MIN) {
        return 5;
    }

    return 9;
}

static size_t otel_cfl_string_header_size(size_t length)
{
    if (length <= 31) {
        return 1;
    }
    if (length <= UINT8_MAX) {
        return 2;
    }
    if (length <= UINT16_MAX) {
        return 3;
    }

    return 5;
}

static size_t otel_cfl_binary_header_size(size_t length)
{
    if (length <= UINT8_MAX) {
        return 2;
    }
    if (length <= UINT16_MAX) {
        return 3;
    }

    return 5;
}

static size_t otel_cfl_array_header_size(size_t entries)
{
    if (entries <= 15) {
        return 1;
    }
    if (entries <= UINT16_MAX) {
        return 3;
    }

    return 5;
}

static int otel_cfl_account_sized_value(struct otel_cfl_builder *builder,
                                        size_t header_size, size_t value_size)
{
    if (otel_cfl_account(builder, header_size) != 0) {
        return -1;
    }

    return otel_cfl_account(builder, value_size);
}

static struct cfl_variant *otel_cfl_string(struct otel_cfl_builder *builder,
                                           char *str, size_t len)
{
    if (otel_cfl_account_sized_value(builder,
                                     otel_cfl_string_header_size(len), len) != 0) {
        return NULL;
    }

    return cfl_variant_create_from_string_s_in(builder->arena, str, len, CFL_TRUE);
}

static struct cfl_variant *otel_cfl_bytes(struct otel_cfl_builder *builder,
                                          ProtobufCBinaryData bytes)
{
    if (otel_cfl_account_sized_value(builder,
                                     otel_cfl_binary_header_size(bytes.len),
                                     bytes.len) != 0) {
        return NULL;
    }

    return cfl_variant_create_from_bytes_in(builder->arena,
                                             (char *) bytes.data, bytes.len, CFL_TRUE);
}

static struct cfl_variant *otel_cfl_uint(struct otel_cfl_builder *builder, uint64_t val)
{
    if (otel_cfl_account(builder, otel_cfl_uint_size(val)) != 0) {
        return NULL;
    }

    return cfl_variant_create_from_uint64_in(builder->arena, val);
}

/* msgpack keeps non-negative integers as unsigned values */
static struct cfl_variant *otel_cfl_int(struct otel_cfl_builder *builder, int64_t val)
{
    if (val >= 0) {
        return otel_cfl_uint(builder, (uint64_t) val);
    }

    if (otel_cfl_account(builder, otel_cfl_int_size(val)) != 0) {
        return NULL;
    }

    return cfl_variant_create_from_int64_in(builder->arena, val);
}

/* Insert a value, the value is released when it cannot be inserted */
static int otel_cfl_insert(struct otel_cfl_builder *builder, struct cfl_kvlist *kvlist,
                           const char *key, size_t key_len, struct cfl_variant *value)
{
    if (value == NULL) {
        return -1;
    }

    if (otel_cfl_account_sized_value(builder,
                                     otel_cfl_string_header_size(key_len),
                                     key_len) != 0 ||
        cfl_kvlist_insert_s(kvlist, (char *) key, key_len, value) != 0) {
        cfl_variant_destroy(value);
        return -1;
    }

    return 0;
}

/* Insert a kvlist, the kvlist is released when it cannot be inserted */
static int otel_cfl_insert_kvlist(struct otel_cfl_builder *builder,
                                  struct cfl_kvlist *kvlist,
                                  const char *key, size_t key_len,
                                  struct cfl_kvlist *value)
{
    struct cfl_variant *variant;

    if (value == NULL) {
        return -1;
    }

    variant = cfl_variant_create_from_kvlist_in(builder->arena, value);
    if (variant == NULL) {
        cfl_kvlist_destroy(value);
        return -1;
    }

    return otel_cfl_insert(builder, kvlist, key, key_len, variant);
}

static struct cfl_kvlist *otel_cfl_kvlist_create(struct otel_cfl_builder *builder)
{
    /* CFL's dynamic map encoder reserves a map32 header for every kvlist. */
    if (otel_cfl_account(builder, OTEL_CFL_MAP_HEADER_SIZE) != 0) {
        return NULL;
    }

    return cfl_kvlist_create_in(builder->arena);
}

/* A map the msgpack path packs with a compact header */
static struct cfl_kvlist *otel_cfl_kvlist_create_compact(struct otel_cfl_builder *builder,
                                                         size_t entries)
{
    if (otel_cfl_account(builder, otel_cfl_array_header_size(entries)) != 0) {
        return NULL;
    }

    return cfl_kvlist_create_in(builder->arena);
}

static struct cfl_variant *otel_cfl_any_value(struct otel_cfl_builder *builder,
                                              Opentelemetry__Proto__Common__V1__AnyValue *value);

static struct cfl_kvlist *otel_cfl_kvarray(struct otel_cfl_builder *builder,
                                           Opentelemetry__Proto__Common__V1__KeyValue **kv_array,
                                           size_t kv_count)
{
    size_t index;
    struct cfl_kvlist *kvlist;

    kvlist = otel_cfl_kvlist_create_compact(builder, kv_count);
    if (kvlist == NULL) {
        return NULL;
    }

    for (index = 0; index < kv_count; index++) {
        if (otel_cfl_insert(builder, kvlist,
                            kv_array[index]->key, strlen(kv_array[index]->key),
                            otel_cfl_any_value(builder, kv_array[index]->value)) != 0) {
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }
    }

    return kvlist;
}

static struct cfl_variant *otel_cfl_array(struct otel_cfl_builder *builder,
                                          Opentelemetry__Proto__Common__V1__ArrayValue *array)
{
    size_t index;
    struct cfl_array *entries;
    struct cfl_variant *entry;
    struct cfl_variant *variant;

    if (otel_cfl_account(builder,
                         otel_cfl_array_header_size(array->n_values)) != 0) {
        return NULL;
    }

    entries = cfl_array_create_in(builder->arena, array->n_values);
    if (entries == NULL) {
        return NULL;
    }

    for (index = 0; index < array->n_values; index++) {
        entry = otel_cfl_any_value(builder, array->values[index]);
        if (entry == NULL || cfl_array_append(entries, entry) != 0) {
            if (entry != NULL) {
                cfl_variant_destroy(entry);
            }
            cfl_array_destroy(entries);
            return NULL;
        }
    }

    variant = cfl_variant_create_from_array_in(builder->arena, entries);
    if (variant == NULL) {
        cfl_array_destroy(entries);
    }

    return variant;
}

static struct cfl_variant *otel_cfl_any_value(struct otel_cfl_builder *builder,
                                              Opentelemetry__Proto__Common__V1__AnyValue *value)
{
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;

    if (value == NULL) {
        if (otel_cfl_account(builder, 1) != 0) {
            return NULL;
        }
        return cfl_variant_create_from_null_in(builder->arena);
    }

    switch (value->value_case) {
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE:
        return otel_cfl_string(builder, value->string_value, strlen(value->string_value));

    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE:
        if (otel_cfl_account(builder, 1) != 0) {
            return NULL;
        }
        return cfl_variant_create_from_bool_in(builder->arena, value->bool_value);

    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE:
        return otel_cfl_int(builder, value->int_value);

    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE:
        if (otel_cfl_account(builder, 9) != 0) {
            return NULL;
        }
        return cfl_variant_create_from_double_in(builder->arena, value->double_value);

    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE:
        return otel_cfl_array(builder, value->array_value);

    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE:
        kvlist = otel_cfl_kvarray(builder, value->kvlist_value->values,
                                  value->kvlist_value->n_values);
        if (kvlist == NULL) {
            return NULL;
        }

        variant = cfl_variant_create_from_kvlist_in(builder->arena, kvlist);
        if (variant == NULL) {
            cfl_kvlist_destroy(kvlist);
        }
        return variant;

    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE:
        return otel_cfl_bytes(builder, value->bytes_value);

    /* profiling-only string dictionary references are ignored in logs */
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX:
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE__NOT_SET:
        if (otel_cfl_account(builder, 1) != 0) {
            return NULL;
        }
        return cfl_variant_create_from_null_in(builder->arena);

    default:
        flb_error("[otel]: invalid value type in pack_any_value");
        return NULL;
    }
}

/* Wrap a kvlist as a record object, the kvlist is released on failure */
static struct cfl_object *otel_cfl_object(struct otel_cfl_builder *builder,
                                          struct cfl_kvlist *kvlist)
{
    struct cfl_object *object;

    if (kvlist == NULL) {
        return NULL;
    }

    object = cfl_object_create();
    if (object == NULL) {
        cfl_kvlist_destroy(kvlist);
        return NULL;
    }

    object->variant = cfl_variant_create_from_kvlist_in(builder->arena, kvlist);
    if (object->variant == NULL) {
        cfl_kvlist_destroy(kvlist);
        cfl_object_destroy(object);
        return NULL;
    }
    object->type = CFL_OBJECT_KVLIST;

    return object;
}

/* Append a record to the chunk, its objects are owned by the chunk */
static struct flb_mp_chunk_record *otel_cfl_record_add(struct otel_cfl_builder *builder,
                                                       struct flb_time *tm)
{
    struct flb_mp_chunk_record *record;

    if (otel_cfl_account(builder, OTEL_CFL_RECORD_SIZE) != 0) {
        return NULL;
    }

    record = flb_mp_chunk_record_create(builder->chunk);
    if (record == NULL) {
        return NULL;
    }

    memset(&record->event, 0, sizeof(record->event));
    flb_time_copy(&record->event.timestamp, tm);
    cfl_list_add(&record->_head, &builder->chunk->records);

    return record;
}

/* https://opentelemetry.io/docs/specs/otel/logs/data-model/#log-and-event-record-definition */
static struct cfl_kvlist *otel_cfl_v1_metadata(
    struct otel_cfl_builder *builder,
    Opentelemetry__Proto__Logs__V1__LogRecord *log_record)
{
    int ret = 0;
    struct cfl_kvlist *otlp;
    struct cfl_kvlist *metadata;

    metadata = otel_cfl_kvlist_create(builder);
    otlp = otel_cfl_kvlist_create(builder);
    if (metadata == NULL || otlp == NULL) {
        goto error;
    }

    if (log_record->observed_time_unix_nano != 0) {
        ret = otel_cfl_insert(builder, otlp, "observed_timestamp", 18,
                              otel_cfl_uint(builder, log_record->observed_time_unix_nano));
    }

    /* Value of 0 indicates unknown or missing timestamp. */
    if (ret == 0 && log_record->time_unix_nano != 0) {
        ret = otel_cfl_insert(builder, otlp, "timestamp", 9,
                              otel_cfl_uint(builder, log_record->time_unix_nano));
    }

    /* https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber */
    if (ret == 0 && log_record->severity_number >= 1 && log_record->severity_number <= 24) {
        ret = otel_cfl_insert(builder, otlp, "severity_number", 15,
                              otel_cfl_uint(builder, log_record->severity_number));
    }

    if (ret == 0 && log_record->severity_text != NULL &&
        strlen(log_record->severity_text) > 0) {
        ret = otel_cfl_insert(builder, otlp, "severity_text", 13,
                              otel_cfl_string(builder, log_record->severity_text,
                                              strlen(log_record->severity_text)));
    }

    if (ret == 0 && log_record->n_attributes > 0) {
        ret = otel_cfl_insert_kvlist(builder, otlp, "attributes", 10,
                                     otel_cfl_kvarray(builder, log_record->attributes,
                                                      log_record->n_attributes));
    }

    if (ret == 0 && log_record->dropped_attributes_count > 0) {
        ret = otel_cfl_insert(builder, otlp, "dropped_attributes_count", 24,
                              otel_cfl_uint(builder, log_record->dropped_attributes_count));
    }

    if (ret == 0 && log_record->trace_id.len > 0) {
        ret = otel_cfl_insert(builder, otlp, "trace_id", 8,
                              otel_cfl_bytes(builder, log_record->trace_id));
    }

    if (ret == 0 && log_record->span_id.len > 0) {
        ret = otel_cfl_insert(builder, otlp, "span_id", 7,
                              otel_cfl_bytes(builder, log_record->span_id));
    }

    if (ret == 0) {
        ret = otel_cfl_insert(builder, otlp, "trace_flags", 11,
                              otel_cfl_uint(builder, log_record->flags & 0xff));
    }

    if (ret == 0 && log_record->event_name != NULL && strlen(log_record->event_name) > 0) {
        ret = otel_cfl_insert(builder, otlp, "event_name", 10,
                              otel_cfl_string(builder, log_record->event_name,
                                              strlen(log_record->event_name)));
    }

    if (ret != 0) {
        goto error;
    }

    ret = otel_cfl_insert_kvlist(builder, metadata, builder->options->metadata_key,
                                 strlen(builder->options->metadata_key), otlp);
    otlp = NULL;
    if (ret != 0) {
        goto error;
    }

    return metadata;

error:
    if (otlp != NULL) {
        cfl_kvlist_destroy(otlp);
    }
    if (metadata != NULL) {
        cfl_kvlist_destroy(metadata);
    }
    return NULL;
}

static struct cfl_kvlist *otel_cfl_body(struct otel_cfl_builder *builder,
                                        Opentelemetry__Proto__Common__V1__AnyValue *body)
{
    const char *logs_body_key;
    struct cfl_kvlist *kvlist;

    if (builder->options->body_key == NULL && body != NULL &&
        body->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
        return otel_cfl_kvarray(builder, body->kvlist_value->values,
                                body->kvlist_value->n_values);
    }

    logs_body_key = builder->options->body_key;
    if (logs_body_key == NULL) {
        logs_body_key = "log";
    }

    kvlist = otel_cfl_kvlist_create_compact(builder, 1);
    if (kvlist == NULL) {
        return NULL;
    }

    if (otel_cfl_insert(builder, kvlist, logs_body_key, strlen(logs_body_key),
                        otel_cfl_any_value(builder, body)) != 0) {
        cfl_kvlist_destroy(kvlist);
        return NULL;
    }

    return kvlist;
}

static struct cfl_kvlist *otel_cfl_group_metadata(struct otel_cfl_builder *builder,
                                                  int resource_index, int scope_index)
{
    struct cfl_kvlist *kvlist;

    kvlist = otel_cfl_kvlist_create(builder);
    if (kvlist == NULL) {
        return NULL;
    }

    if (otel_cfl_insert(builder, kvlist, "schema", 6, otel_cfl_string(builder, "otlp", 4)) != 0 ||
        otel_cfl_insert(builder, kvlist, "resource_id", 11,
                        otel_cfl_int(builder, resource_index)) != 0 ||
        otel_cfl_insert(builder, kvlist, "scope_id", 8,
                        otel_cfl_int(builder, scope_index)) != 0) {
        cfl_kvlist_destroy(kvlist);
        return NULL;
    }

    return kvlist;
}

static struct cfl_kvlist *otel_cfl_group_body(
    struct otel_cfl_builder *builder,
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log,
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log)
{
    int ret = 0;
    struct cfl_kvlist *body;
    struct cfl_kvlist *resource_kv;
    struct cfl_kvlist *scope_kv;
    Opentelemetry__Proto__Resource__V1__Resource *resource;
    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope;

    body = otel_cfl_kvlist_create(builder);
    resource_kv = otel_cfl_kvlist_create(builder);
    scope_kv = otel_cfl_kvlist_create(builder);
    if (body == NULL || resource_kv == NULL || scope_kv == NULL) {
        goto error;
    }

    resource = resource_log->resource;
    if (resource) {
        /* look for OTel resource attributes */
        if (resource->n_attributes > 0 && resource->attributes) {
            ret = otel_cfl_insert_kvlist(builder, resource_kv, "attributes", 10,
                                         otel_cfl_kvarray(builder, resource->attributes,
                                                          resource->n_attributes));
        }

        if (ret == 0 && resource->dropped_attributes_count > 0) {
            ret = otel_cfl_insert(builder, resource_kv, "dropped_attributes_count", 24,
                                  otel_cfl_uint(builder, resource->dropped_attributes_count));
        }

        if (ret == 0 && resource_log->schema_url) {
            ret = otel_cfl_insert(builder, resource_kv, "schema_url", 10,
                                  otel_cfl_string(builder, resource_log->schema_url,
                                                  strlen(resource_log->schema_url)));
        }
    }

    scope = scope_log->scope;
    if (ret == 0 && scope_log->schema_url && strlen(scope_log->schema_url) > 0) {
        ret = otel_cfl_insert(builder, scope_kv, "schema_url", 10,
                              otel_cfl_string(builder, scope_log->schema_url,
                                              strlen(scope_log->schema_url)));
    }

    if (scope) {
        if (ret == 0 && scope->name && strlen(scope->name) > 0) {
            ret = otel_cfl_insert(builder, scope_kv, "name", 4,
                                  otel_cfl_string(builder, scope->name, strlen(scope->name)));
        }

        if (ret == 0 && scope->version && strlen(scope->version) > 0) {
            ret = otel_cfl_insert(builder, scope_kv, "version", 7,
                                  otel_cfl_string(builder, scope->version,
                                                  strlen(scope->version)));
        }

        if (ret == 0 && scope->n_attributes > 0 && scope->attributes) {
            ret = otel_cfl_insert_kvlist(builder, scope_kv, "attributes", 10,
                                         otel_cfl_kvarray(builder, scope->attributes,
                                                          scope->n_attributes));
        }

        if (ret == 0 && scope->dropped_attributes_count > 0) {
            ret = otel_cfl_insert(builder, scope_kv, "dropped_attributes_count", 24,
                                  otel_cfl_uint(builder, scope->dropped_attributes_count));
        }
    }

    if (ret != 0) {
        goto error;
    }

    ret = otel_cfl_insert_kvlist(builder, body, "resource", 8, resource_kv);
    resource_kv = NULL;
    if (ret == 0) {
        ret = otel_cfl_insert_kvlist(builder, body, "scope", 5, scope_kv);
        scope_kv = NULL;
    }
    if (ret != 0) {
        goto error;
    }

    return body;

error:
    if (scope_kv != NULL) {
        cfl_kvlist_destroy(scope_kv);
    }
    if (resource_kv != NULL) {
        cfl_kvlist_destroy(resource_kv);
    }
    if (body != NULL) {
        cfl_kvlist_destroy(body);
    }
    return NULL;
}

/* Build the group start, records and group end of one scope logs entry */
static int otel_cfl_scope_logs(struct otel_cfl_builder *builder,
                               Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log,
                               Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log,
                               int resource_index, int scope_index,
                               size_t *record_count)
{
    size_t index;
    struct flb_time tm;
    struct flb_mp_chunk_record *group;
    struct flb_mp_chunk_record *record;
    Opentelemetry__Proto__Logs__V1__LogRecord *log_record;

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_START, 0);
    group = otel_cfl_record_add(builder, &tm);
    if (group == NULL) {
        return -1;
    }

    group->cobj_metadata = otel_cfl_object(builder,
                               otel_cfl_group_metadata(builder, resource_index, scope_index));
    group->cobj_record = otel_cfl_object(builder,
                                         otel_cfl_group_body(builder, resource_log, scope_log));
    if (group->cobj_metadata == NULL || group->cobj_record == NULL) {
        return -1;
    }

    /* the group start owns the group content, like a decoded chunk */
    group->cobj_group_metadata = group->cobj_metadata;
    group->cobj_group_attributes = group->cobj_record;
    group->owns_group_metadata = FLB_TRUE;
    group->owns_group_attributes = FLB_TRUE;

    for (index = 0; index < scope_log->n_log_records; index++) {
        log_record = scope_log->log_records[index];

        if (log_record->time_unix_nano > 0) {
            if (flb_time_from_uint64(&tm, log_record->time_unix_nano) != 0) {
                return -1;
            }
        }
        else if (log_record->observed_time_unix_nano > 0) {
            if (flb_time_from_uint64(&tm, log_record->observed_time_unix_nano) != 0) {
                return -1;
            }
        }
        else {
            flb_time_get(&tm);
        }

        record = otel_cfl_record_add(builder, &tm);
        if (record == NULL) {
            return -1;
        }

        record->cobj_metadata = otel_cfl_object(builder,
                                                otel_cfl_v1_metadata(builder, log_record));
        if (record->cobj_metadata == NULL) {
            flb_error("[opentelemetry] failed to convert log record");
            return -1;
        }

        record->cobj_record = otel_cfl_object(builder,
                                              otel_cfl_body(builder, log_record->body));
        if (record->cobj_record == NULL) {
            flb_error("[opentelemetry] failed to convert log record body");
            return -1;
        }

        record->cobj_group_metadata = group->cobj_group_metadata;
        record->cobj_group_attributes = group->cobj_group_attributes;
        (*record_count)++;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_END, 0);
    record = otel_cfl_record_add(builder, &tm);
    if (record == NULL) {
        return -1;
    }

    record->cobj_metadata = otel_cfl_object(builder, otel_cfl_kvlist_create(builder));
    record->cobj_record = otel_cfl_object(builder, otel_cfl_kvlist_create(builder));
    if (record->cobj_metadata == NULL || record->cobj_record == NULL) {
        return -1;
    }
    record->cobj_group_metadata = group->cobj_group_metadata;
    record->cobj_group_attributes = group->cobj_group_attributes;

    return 0;
}

/*
 * CFL records borrow strings and byte arrays from the unpacked protobuf
 * request. Keep the request and its arena alive until the caller consumes the
 * chunk synchronously.
 */
struct flb_opentelemetry_logs_protobuf_cfl {
    struct flb_mp_chunk_cobj *chunk;
    size_t encoded_size;
    size_t record_count;
    struct cfl_arena *protobuf_arena;
    ProtobufCAllocator arena_allocator;
    ProtobufCAllocator *protobuf_allocator;
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *input_logs;
};

int flb_opentelemetry_logs_protobuf_to_cfl(
        const void *payload, size_t payload_size,
        const struct flb_opentelemetry_logs_decode_options *options,
        struct flb_opentelemetry_logs_protobuf_cfl **out_result)
{
    int ret;
    size_t resource_logs_index;
    size_t scope_log_index;
    struct otel_cfl_builder builder;
    struct flb_opentelemetry_logs_protobuf_cfl *result;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;

    if (options == NULL || options->metadata_key == NULL || out_result == NULL ||
        (payload == NULL && payload_size != 0)) {
        return -1;
    }

    *out_result = NULL;
    result = flb_calloc(1, sizeof(struct flb_opentelemetry_logs_protobuf_cfl));
    if (result == NULL) {
        flb_errno();
        return -1;
    }

    builder.options = options;
    builder.arena = NULL;
    builder.size = 0;
    builder.limit = options->output_limit;
    builder.chunk = NULL;
    ret = 0;

    result->input_logs = protobuf_logs_decode(
                             (uint8_t *) payload, payload_size,
                             &result->protobuf_arena,
                             &result->arena_allocator,
                             &result->protobuf_allocator);
    if (result->input_logs == NULL) {
        flb_warn("[opentelemetry] failed to unpack protobuf logs payload");
        ret = -1;
        goto end;
    }
    /*
     * The CFL tree is consumed and encoded synchronously before the decoded
     * protobuf request is released, so both representations can safely share
     * the request arena. This avoids one heap allocation per CFL container and
     * scalar while preserving the normal allocator fallback for small payloads.
     */
    builder.arena = result->protobuf_arena;

    if (result->input_logs->n_resource_logs > 0 &&
        result->input_logs->resource_logs == NULL) {
        flb_warn("[opentelemetry] no resource logs found");
        ret = -1;
        goto end;
    }

    builder.chunk = flb_mp_chunk_cobj_create(NULL, NULL);
    if (builder.chunk == NULL) {
        ret = -1;
        goto end;
    }
    builder.chunk->record_pool_enabled = FLB_TRUE;

    for (resource_logs_index = 0;
         resource_logs_index < result->input_logs->n_resource_logs;
         resource_logs_index++) {
        resource_log = result->input_logs->resource_logs[resource_logs_index];
        if (resource_log == NULL) {
            flb_warn("[opentelemetry] null resource logs entry found");
            ret = -1;
            goto end;
        }

        if (resource_log->n_scope_logs > 0 && resource_log->scope_logs == NULL) {
            flb_warn("[opentelemetry] no scope logs found");
            ret = -1;
            goto end;
        }

        for (scope_log_index = 0; scope_log_index < resource_log->n_scope_logs;
             scope_log_index++) {
            scope_log = resource_log->scope_logs[scope_log_index];
            if (scope_log == NULL) {
                flb_warn("[opentelemetry] null scope logs entry found");
                ret = -1;
                goto end;
            }
            if (scope_log->n_log_records == 0) {
                continue;
            }
            if (scope_log->log_records == NULL) {
                flb_warn("[opentelemetry] no log records found");
                ret = -1;
                goto end;
            }

            ret = otel_cfl_scope_logs(&builder, resource_log, scope_log,
                                      resource_logs_index, scope_log_index,
                                      &result->record_count);
            if (ret != 0) {
                flb_error("[opentelemetry] marshalling error");
                goto end;
            }
        }
    }

    result->encoded_size = builder.size;
    result->chunk = builder.chunk;
    builder.chunk = NULL;
    *out_result = result;

end:
    if (builder.chunk != NULL) {
        flb_mp_chunk_cobj_destroy(builder.chunk);
    }
    if (ret != 0) {
        flb_opentelemetry_logs_protobuf_cfl_destroy(result);
        return -1;
    }

    return 0;
}

struct flb_mp_chunk_cobj *flb_opentelemetry_logs_protobuf_cfl_take_chunk(
        struct flb_opentelemetry_logs_protobuf_cfl *result)
{
    struct flb_mp_chunk_cobj *chunk;

    if (result == NULL) {
        return NULL;
    }

    chunk = result->chunk;
    result->chunk = NULL;

    return chunk;
}

size_t flb_opentelemetry_logs_protobuf_cfl_get_encoded_size(
        struct flb_opentelemetry_logs_protobuf_cfl *result)
{
    if (result == NULL) {
        return 0;
    }

    return result->encoded_size;
}

void flb_opentelemetry_logs_protobuf_cfl_destroy(
        struct flb_opentelemetry_logs_protobuf_cfl *result)
{
    if (result == NULL) {
        return;
    }

    if (result->chunk != NULL) {
        flb_mp_chunk_cobj_destroy(result->chunk);
    }
    if (result->input_logs != NULL) {
        protobuf_logs_free(result->input_logs, result->protobuf_allocator);
    }
    cfl_arena_destroy(result->protobuf_arena);
    flb_free(result);
}
