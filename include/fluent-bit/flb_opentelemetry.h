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

#ifndef FLB_OPENTELEMETRY_H
#define FLB_OPENTELEMETRY_H

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_sds.h>
#include <cfl/cfl.h>
#include <msgpack.h>
#include <stdint.h>

/* Error code values from flb_opentelemetry logs/traces helpers */
#define FLB_OTEL_LOGS_ERR_GENERIC_ERROR                     -1
#define FLB_OTEL_TRACES_ERR_GENERIC_ERROR                   -1

enum {

    /* resource errors */
    FLB_OTEL_RESOURCE_INVALID_ATTRIBUTE = 1,
    FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE,
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
    FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE,
    FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID,
    FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID,

    /* trace specific errors */
    FLB_OTEL_TRACES_ERR_UNEXPECTED_ROOT_OBJECT_TYPE,
    FLB_OTEL_TRACES_ERR_INVALID_JSON,
    FLB_OTEL_TRACES_ERR_RESOURCE_SPANS_MISSING,
    FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_TYPE,
    FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_ENTRY_TYPE,
    FLB_OTEL_TRACES_ERR_SCOPE_SPANS_MISSING,
    FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_TYPE,
    FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_ENTRY_TYPE,
    FLB_OTEL_TRACES_ERR_SPANS_MISSING,
    FLB_OTEL_TRACES_ERR_UNEXPECTED_SPANS_TYPE,
    FLB_OTEL_TRACES_ERR_UNEXPECTED_SPAN_ENTRY_TYPE,
    FLB_OTEL_TRACES_ERR_SPAN_NAME_MISSING,
    FLB_OTEL_TRACES_ERR_INVALID_ATTRIBUTES,
    FLB_OTEL_TRACES_ERR_INVALID_TRACE_ID,
    FLB_OTEL_TRACES_ERR_INVALID_SPAN_ID,
    FLB_OTEL_TRACES_ERR_INVALID_PARENT_SPAN_ID,
    FLB_OTEL_TRACES_ERR_INVALID_EVENT_ENTRY,
    FLB_OTEL_TRACES_ERR_INVALID_EVENT_TIMESTAMP,
    FLB_OTEL_TRACES_ERR_INVALID_LINK_ENTRY,
    FLB_OTEL_TRACES_ERR_INVALID_LINK_TRACE_ID,
    FLB_OTEL_TRACES_ERR_INVALID_LINK_SPAN_ID,
    FLB_OTEL_TRACES_ERR_STATUS_FAILURE
};


/*
 * This is not specifically an error but a way to specify why no
 * data was ingested
 */
#define FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD                      100


struct flb_otel_error_map {
    const char *name;
    int code;
};

struct cmt;
struct ctrace;
struct flb_log_event;

enum flb_opentelemetry_otlp_json_result {
    FLB_OPENTELEMETRY_OTLP_JSON_SUCCESS = 0,
    FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT = -1,
    FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED = -2,
    FLB_OPENTELEMETRY_OTLP_JSON_INVALID_LOG_EVENT = -3
};

enum flb_opentelemetry_otlp_proto_result {
    FLB_OPENTELEMETRY_OTLP_PROTO_SUCCESS = 0,
    FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_ARGUMENT = -1,
    FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED = -2,
    FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_LOG_EVENT = -3
};

struct flb_opentelemetry_otlp_logs_options {
    int logs_require_otel_metadata;
    const char *logs_body_key;
    const char **logs_body_keys;
    size_t logs_body_key_count;
    int logs_body_key_attributes;
};

/* Backward-compatible alias for older external callers. */
#define flb_opentelemetry_otlp_json_options flb_opentelemetry_otlp_logs_options

static struct flb_otel_error_map otel_error_map[] = {
    {"FLB_OTEL_RESOURCE_INVALID_ATTRIBUTE",                  FLB_OTEL_RESOURCE_INVALID_ATTRIBUTE},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE",        FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE},
    {"FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING",               FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE",       FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_ENTRY_TYPE", FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_ENTRY_TYPE},
    {"FLB_OTEL_LOGS_ERR_SCOPELOGS_MISSING",                  FLB_OTEL_LOGS_ERR_SCOPELOGS_MISSING},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE",          FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE},
    {"FLB_OTEL_LOGS_ERR_GROUP_METADATA",                     FLB_OTEL_LOGS_ERR_GROUP_METADATA},
    {"FLB_OTEL_LOGS_ERR_SCOPE_METADATA",                     FLB_OTEL_LOGS_ERR_SCOPE_METADATA},
    {"FLB_OTEL_LOGS_ERR_SCOPE_KVLIST",                       FLB_OTEL_LOGS_ERR_SCOPE_KVLIST},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE",   FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE},
    {"FLB_OTEL_LOGS_ERR_MISSING_TIMESTAMP",                  FLB_OTEL_LOGS_ERR_MISSING_TIMESTAMP},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE",          FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE",         FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE",               FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE},
    {"FLB_OTEL_LOGS_ERR_MISSING_LOGRECORDS",                 FLB_OTEL_LOGS_ERR_MISSING_LOGRECORDS},
    {"FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE",         FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE},
    {"FLB_OTEL_LOGS_ERR_ENCODER_FAILURE",                    FLB_OTEL_LOGS_ERR_ENCODER_FAILURE},
    {"FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE",                FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE},
    {"FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID",                   FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID},
    {"FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID",                    FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID},

    {"FLB_OTEL_TRACES_ERR_UNEXPECTED_ROOT_OBJECT_TYPE",      FLB_OTEL_TRACES_ERR_UNEXPECTED_ROOT_OBJECT_TYPE},
    {"FLB_OTEL_TRACES_ERR_INVALID_JSON",                     FLB_OTEL_TRACES_ERR_INVALID_JSON},
    {"FLB_OTEL_TRACES_ERR_RESOURCE_SPANS_MISSING",           FLB_OTEL_TRACES_ERR_RESOURCE_SPANS_MISSING},
    {"FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_TYPE",   FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_TYPE},
    {"FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_ENTRY_TYPE", FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_ENTRY_TYPE},
    {"FLB_OTEL_TRACES_ERR_SCOPE_SPANS_MISSING",              FLB_OTEL_TRACES_ERR_SCOPE_SPANS_MISSING},
    {"FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_TYPE",      FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_TYPE},
    {"FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_ENTRY_TYPE",FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_ENTRY_TYPE},
    {"FLB_OTEL_TRACES_ERR_SPANS_MISSING",                    FLB_OTEL_TRACES_ERR_SPANS_MISSING},
    {"FLB_OTEL_TRACES_ERR_UNEXPECTED_SPANS_TYPE",            FLB_OTEL_TRACES_ERR_UNEXPECTED_SPANS_TYPE},
    {"FLB_OTEL_TRACES_ERR_UNEXPECTED_SPAN_ENTRY_TYPE",       FLB_OTEL_TRACES_ERR_UNEXPECTED_SPAN_ENTRY_TYPE},
    {"FLB_OTEL_TRACES_ERR_SPAN_NAME_MISSING",                FLB_OTEL_TRACES_ERR_SPAN_NAME_MISSING},
    {"FLB_OTEL_TRACES_ERR_INVALID_ATTRIBUTES",               FLB_OTEL_TRACES_ERR_INVALID_ATTRIBUTES},
    {"FLB_OTEL_TRACES_ERR_INVALID_TRACE_ID",                 FLB_OTEL_TRACES_ERR_INVALID_TRACE_ID},
    {"FLB_OTEL_TRACES_ERR_INVALID_SPAN_ID",                  FLB_OTEL_TRACES_ERR_INVALID_SPAN_ID},
    {"FLB_OTEL_TRACES_ERR_INVALID_PARENT_SPAN_ID",           FLB_OTEL_TRACES_ERR_INVALID_PARENT_SPAN_ID},
    {"FLB_OTEL_TRACES_ERR_INVALID_EVENT_ENTRY",              FLB_OTEL_TRACES_ERR_INVALID_EVENT_ENTRY},
    {"FLB_OTEL_TRACES_ERR_INVALID_EVENT_TIMESTAMP",          FLB_OTEL_TRACES_ERR_INVALID_EVENT_TIMESTAMP},
    {"FLB_OTEL_TRACES_ERR_INVALID_LINK_ENTRY",               FLB_OTEL_TRACES_ERR_INVALID_LINK_ENTRY},
    {"FLB_OTEL_TRACES_ERR_INVALID_LINK_TRACE_ID",            FLB_OTEL_TRACES_ERR_INVALID_LINK_TRACE_ID},
    {"FLB_OTEL_TRACES_ERR_INVALID_LINK_SPAN_ID",             FLB_OTEL_TRACES_ERR_INVALID_LINK_SPAN_ID},
    {"FLB_OTEL_TRACES_ERR_STATUS_FAILURE",                   FLB_OTEL_TRACES_ERR_STATUS_FAILURE},
    {"GENERIC_ERROR",                                        FLB_OTEL_LOGS_ERR_GENERIC_ERROR},
    {"FLB_OTEL_TRACES_ERR_GENERIC_ERROR",                    FLB_OTEL_TRACES_ERR_GENERIC_ERROR},

    /* ---- */
    {"FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD",                      FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD},
    {NULL, 0}
};

static inline const char *flb_opentelemetry_error_to_string(int err_code)
{
    int i;

    for (i = 0; otel_error_map[i].name != NULL; i++) {
        if (otel_error_map[i].code == err_code) {
            return otel_error_map[i].name;
        }
    }
    return "Unknown error code";
}

static inline int flb_opentelemetry_error_code(const char *err_msg)
{
    int i;

    for (i = 0; otel_error_map[i].name != NULL; i++) {
        if (strcmp(otel_error_map[i].name, err_msg) == 0) {
            return otel_error_map[i].code;
        }
    }
    return -1000;
}

int flb_opentelemetry_logs_json_to_msgpack(struct flb_log_event_encoder *encoder,
                                           const char *body, size_t len,
                                           const char *logs_body_key,
                                           int *error_status);

int flb_opentelemetry_metrics_json_to_cmt(struct cfl_list *context_list,
                                          const char *body, size_t len);

struct ctrace *flb_opentelemetry_json_traces_to_ctrace(const char *body, size_t len,
                                                       int *error_status);

/*
 * OTLP JSON encoding entry points shared by outputs and processors.
 * Traces and metrics are intentionally typed to keep transport plugins
 * independent from OpenTelemetry schema details.
 */
flb_sds_t flb_opentelemetry_traces_to_otlp_json(struct ctrace *context,
                                                int *result);

flb_sds_t flb_opentelemetry_traces_msgpack_to_otlp_json(const void *data,
                                                        size_t size,
                                                        int *result);

flb_sds_t flb_opentelemetry_traces_msgpack_to_otlp_json_pretty(const void *data,
                                                               size_t size,
                                                               int *result);

flb_sds_t flb_opentelemetry_metrics_to_otlp_json(struct cmt *context,
                                                 int *result);

flb_sds_t flb_opentelemetry_metrics_msgpack_to_otlp_json(const void *data,
                                                         size_t size,
                                                         int *result);

flb_sds_t flb_opentelemetry_metrics_msgpack_to_otlp_json_pretty(const void *data,
                                                                size_t size,
                                                                int *result);

flb_sds_t flb_opentelemetry_logs_to_otlp_json(const void *event_chunk_data,
                                              size_t event_chunk_size,
                                              struct flb_opentelemetry_otlp_logs_options *options,
                                              int *result);

flb_sds_t flb_opentelemetry_logs_to_otlp_json_pretty(const void *event_chunk_data,
                                                     size_t event_chunk_size,
                                                     struct flb_opentelemetry_otlp_logs_options *options,
                                                     int *result);

/*
 * OTLP protobuf encoding entry points.
 * Destroy returned payloads with the matching flb_opentelemetry_*_proto_destroy()
 * helper instead of calling flb_sds_destroy() or backend-specific encoders
 * directly.
 */
flb_sds_t flb_opentelemetry_traces_to_otlp_proto(struct ctrace *context,
                                                 int *result);

flb_sds_t flb_opentelemetry_metrics_to_otlp_proto(struct cmt *context,
                                                  int *result);

flb_sds_t flb_opentelemetry_metrics_msgpack_to_otlp_proto(const void *data,
                                                          size_t size,
                                                          int *result);

flb_sds_t flb_opentelemetry_logs_to_otlp_proto(const void *event_chunk_data,
                                               size_t event_chunk_size,
                                               struct flb_opentelemetry_otlp_logs_options *options,
                                               int *result);

void flb_opentelemetry_traces_proto_destroy(flb_sds_t payload);
void flb_opentelemetry_metrics_proto_destroy(flb_sds_t payload);
void flb_opentelemetry_logs_proto_destroy(flb_sds_t payload);

int flb_opentelemetry_log_is_otlp(struct flb_log_event *log_event);

int flb_opentelemetry_logs_chunk_is_otlp(const void *event_chunk_data,
                                         size_t event_chunk_size);

/* OpenTelemetry utils */
int flb_otel_utils_find_map_entry_by_key(msgpack_object_map *map,
                                         char *key,
                                         size_t match_index,
                                         int case_insensitive);

int flb_otel_utils_json_payload_get_wrapped_value(msgpack_object *wrapper,
                                         msgpack_object **value,
                                         int            *type);

int flb_otel_utils_json_payload_append_converted_value(struct flb_log_event_encoder *encoder,
                                                       int target_field,
                                                       msgpack_object *object);

int flb_otel_utils_json_payload_append_unwrapped_value(struct flb_log_event_encoder *encoder,
                                                       int target_field,
                                                       msgpack_object *object,
                                                       int *encoder_result);

int flb_otel_utils_json_payload_append_converted_map(struct flb_log_event_encoder *encoder,
                                                     int target_field,
                                                     msgpack_object *object);

int flb_otel_utils_json_payload_append_converted_array(struct flb_log_event_encoder *encoder,
                                                       int target_field,
                                                       msgpack_object *object);

int flb_otel_utils_json_payload_append_converted_kvlist(struct flb_log_event_encoder *encoder,
                                                        int target_field,
                                                        msgpack_object *object);

struct cfl_variant *flb_otel_utils_msgpack_object_to_cfl_variant(
                        msgpack_object *object);

int flb_otel_utils_clone_kvlist_from_otlp_json_array(struct cfl_kvlist *target,
                                                      msgpack_object *attributes_object);

int flb_otel_utils_hex_to_id(const char *str, int len, unsigned char *out_buf, int out_size);

uint64_t flb_otel_utils_convert_string_number_to_u64(char *str, size_t len);

#endif
