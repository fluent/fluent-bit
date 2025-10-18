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

#ifndef FLB_OPENTELEMETRY_H
#define FLB_OPENTELEMETRY_H

#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>
#include <stdint.h>

/* Error code values from flb_opentelemetry_logs.c */
#define FLB_OTEL_LOGS_ERR_GENERIC_ERROR                     -1

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
    FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID
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
    {"GENERIC_ERROR",                                        FLB_OTEL_LOGS_ERR_GENERIC_ERROR},

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

struct ctrace *flb_opentelemetry_json_traces_to_ctrace(const char *body, size_t len,
                                                       int *error_status);

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

int flb_otel_utils_hex_to_id(const char *str, int len, unsigned char *out_buf, int out_size);

uint64_t flb_otel_utils_convert_string_number_to_u64(char *str, size_t len);

#endif
