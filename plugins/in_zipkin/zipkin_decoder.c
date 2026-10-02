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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>

#include <ctraces/ctraces.h>

#include <errno.h>
#include <math.h>
#include <stdint.h>

#include "zipkin_decoder.h"

#define ZIPKIN_MICROSECONDS_TO_NANOSECONDS 1000ULL

static void set_error(char error[ZIPKIN_DECODE_ERROR_SIZE],
                      size_t span_index, const char *message)
{
    if (span_index == SIZE_MAX) {
        snprintf(error, ZIPKIN_DECODE_ERROR_SIZE, "%s\n", message);
    }
    else {
        snprintf(error, ZIPKIN_DECODE_ERROR_SIZE,
                 "span %zu: %s\n", span_index, message);
    }
}

static msgpack_object *map_get(msgpack_object_map *map, const char *key)
{
    size_t index;
    size_t key_length;
    msgpack_object_kv *entry;

    key_length = strlen(key);

    for (index = 0; index < map->size; index++) {
        entry = &map->ptr[index];
        if (entry->key.type == MSGPACK_OBJECT_STR &&
            entry->key.via.str.size == key_length &&
            memcmp(entry->key.via.str.ptr, key, key_length) == 0) {
            return &entry->val;
        }
    }

    return NULL;
}

static flb_sds_t object_to_sds(msgpack_object *object)
{
    if (object == NULL || object->type != MSGPACK_OBJECT_STR) {
        return NULL;
    }

    return flb_sds_create_len(object->via.str.ptr, object->via.str.size);
}

static int object_get_uint64(msgpack_object *object, uint64_t *value)
{
    if (object == NULL || object->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return -1;
    }

    *value = object->via.u64;
    return 0;
}

static int decode_hex_character(unsigned char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }

    return -1;
}

static int decode_identifier(msgpack_object *object, unsigned char *output,
                             size_t output_size, int allow_short_trace_id)
{
    int high;
    int low;
    int nonzero;
    size_t index;
    size_t input_size;
    size_t output_offset;

    if (object == NULL || object->type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    input_size = object->via.str.size;
    if (input_size != output_size * 2) {
        if (allow_short_trace_id == FLB_FALSE ||
            input_size != (output_size / 2) * 2) {
            return -1;
        }
    }

    memset(output, 0, output_size);
    output_offset = output_size - (input_size / 2);
    nonzero = FLB_FALSE;

    for (index = 0; index < input_size / 2; index++) {
        high = decode_hex_character(object->via.str.ptr[index * 2]);
        low = decode_hex_character(object->via.str.ptr[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }

        output[output_offset + index] = (high << 4) | low;
        if (output[output_offset + index] != 0) {
            nonzero = FLB_TRUE;
        }
    }

    return nonzero == FLB_TRUE ? 0 : -1;
}

static int set_span_string_attribute(struct ctrace_span *span,
                                     const char *key,
                                     msgpack_object *value)
{
    int ret;
    flb_sds_t key_string;
    flb_sds_t value_string;

    key_string = flb_sds_create(key);
    value_string = object_to_sds(value);
    if (key_string == NULL || value_string == NULL) {
        flb_sds_destroy(key_string);
        flb_sds_destroy(value_string);
        return -1;
    }

    ret = ctr_span_set_attribute_string(span, key_string, value_string);
    flb_sds_destroy(key_string);
    flb_sds_destroy(value_string);

    return ret;
}

static int set_tag_attribute(struct ctrace_span *span, msgpack_object *key,
                             msgpack_object *value, int parse_string_tags)
{
    int ret;
    int64_t integer_value;
    double double_value;
    char *end;
    flb_sds_t key_string;
    flb_sds_t value_string;

    key_string = object_to_sds(key);
    value_string = object_to_sds(value);
    if (key_string == NULL || value_string == NULL) {
        flb_sds_destroy(key_string);
        flb_sds_destroy(value_string);
        return -1;
    }

    ret = -1;
    if (parse_string_tags == FLB_TRUE && strcmp(value_string, "true") == 0) {
        ret = ctr_span_set_attribute_bool(span, key_string, FLB_TRUE);
    }
    else if (parse_string_tags == FLB_TRUE && strcmp(value_string, "false") == 0) {
        ret = ctr_span_set_attribute_bool(span, key_string, FLB_FALSE);
    }
    else if (parse_string_tags == FLB_TRUE && value_string[0] != '\0') {
        errno = 0;
        end = NULL;
        integer_value = strtoll(value_string, &end, 10);
        if (errno == 0 && end != value_string && *end == '\0') {
            ret = ctr_span_set_attribute_int64(span, key_string, integer_value);
        }
        else {
            errno = 0;
            end = NULL;
            double_value = strtod(value_string, &end);
            if (errno == 0 && end != value_string && *end == '\0' &&
                isfinite(double_value)) {
                ret = ctr_span_set_attribute_double(span, key_string, double_value);
            }
            else {
                ret = ctr_span_set_attribute_string(span, key_string, value_string);
            }
        }
    }
    else {
        ret = ctr_span_set_attribute_string(span, key_string, value_string);
    }

    flb_sds_destroy(key_string);
    flb_sds_destroy(value_string);

    return ret;
}

static int set_endpoint_attributes(struct ctrace_span *span,
                                   struct ctrace_resource *resource,
                                   msgpack_object *endpoint,
                                   int local_endpoint)
{
    int ret;
    uint64_t port;
    msgpack_object *value;
    flb_sds_t string;

    if (endpoint == NULL) {
        return 0;
    }
    if (endpoint->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    value = map_get(&endpoint->via.map, "serviceName");
    if (value != NULL) {
        if (value->type != MSGPACK_OBJECT_STR) {
            return -1;
        }

        string = object_to_sds(value);
        if (string == NULL) {
            return -1;
        }

        if (local_endpoint == FLB_TRUE) {
            ret = ctr_attributes_set_string(resource->attr, "service.name", string);
        }
        else {
            ret = ctr_span_set_attribute_string(span, "service.peer.name", string);
        }
        flb_sds_destroy(string);
        if (ret != 0) {
            return -1;
        }
    }

    value = map_get(&endpoint->via.map, "ipv4");
    if (value == NULL) {
        value = map_get(&endpoint->via.map, "ipv6");
    }
    if (value != NULL) {
        ret = set_span_string_attribute(span,
                                        local_endpoint == FLB_TRUE ?
                                        "network.local.address" :
                                        "network.peer.address",
                                        value);
        if (ret != 0) {
            return -1;
        }
    }

    value = map_get(&endpoint->via.map, "port");
    if (value != NULL) {
        if (object_get_uint64(value, &port) != 0 || port == 0 || port > 65535) {
            return -1;
        }

        ret = ctr_span_set_attribute_int64(span,
                                           local_endpoint == FLB_TRUE ?
                                           "network.local.port" :
                                           "network.peer.port",
                                           (int64_t) port);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static int set_span_kind(struct ctrace_span *span, msgpack_object *kind)
{
    int value;

    if (kind == NULL) {
        value = CTRACE_SPAN_UNSPECIFIED;
    }
    else if (kind->type != MSGPACK_OBJECT_STR) {
        return -1;
    }
    else if (kind->via.str.size == 6 &&
             memcmp(kind->via.str.ptr, "CLIENT", 6) == 0) {
        value = CTRACE_SPAN_CLIENT;
    }
    else if (kind->via.str.size == 6 &&
             memcmp(kind->via.str.ptr, "SERVER", 6) == 0) {
        value = CTRACE_SPAN_SERVER;
    }
    else if (kind->via.str.size == 8 &&
             memcmp(kind->via.str.ptr, "PRODUCER", 8) == 0) {
        value = CTRACE_SPAN_PRODUCER;
    }
    else if (kind->via.str.size == 8 &&
             memcmp(kind->via.str.ptr, "CONSUMER", 8) == 0) {
        value = CTRACE_SPAN_CONSUMER;
    }
    else {
        return -1;
    }

    return ctr_span_kind_set(span, value);
}

static int set_span_status(struct ctrace_span *span, msgpack_object *tags)
{
    int code;
    msgpack_object *error_tag;
    msgpack_object *status_code;
    msgpack_object *status_message;
    flb_sds_t message;

    if (tags == NULL) {
        return 0;
    }

    status_code = map_get(&tags->via.map, "otel.status_code");
    status_message = map_get(&tags->via.map, "otel.status_description");
    error_tag = map_get(&tags->via.map, "error");
    code = CTRACE_SPAN_STATUS_CODE_UNSET;

    if (status_code != NULL) {
        if (status_code->type != MSGPACK_OBJECT_STR) {
            return -1;
        }

        if (status_code->via.str.size == 2 &&
            memcmp(status_code->via.str.ptr, "OK", 2) == 0) {
            code = CTRACE_SPAN_STATUS_CODE_OK;
        }
        else if (status_code->via.str.size == 5 &&
                 memcmp(status_code->via.str.ptr, "ERROR", 5) == 0) {
            code = CTRACE_SPAN_STATUS_CODE_ERROR;
        }
        else if (!(status_code->via.str.size == 5 &&
                   memcmp(status_code->via.str.ptr, "UNSET", 5) == 0)) {
            return -1;
        }
    }

    if (error_tag != NULL) {
        if (error_tag->type != MSGPACK_OBJECT_STR) {
            return -1;
        }
        code = CTRACE_SPAN_STATUS_CODE_ERROR;
    }

    message = NULL;
    if (status_message != NULL) {
        message = object_to_sds(status_message);
        if (message == NULL) {
            return -1;
        }
    }

    if (code != CTRACE_SPAN_STATUS_CODE_UNSET || message != NULL) {
        if (ctr_span_set_status(span, code, message) != 0) {
            flb_sds_destroy(message);
            return -1;
        }
    }
    flb_sds_destroy(message);

    return 0;
}

static int set_span_tags(struct ctrace_span *span, msgpack_object *tags,
                         int parse_string_tags)
{
    size_t index;
    msgpack_object_kv *entry;

    if (tags == NULL) {
        return 0;
    }
    if (tags->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    for (index = 0; index < tags->via.map.size; index++) {
        entry = &tags->via.map.ptr[index];
        if (entry->key.type != MSGPACK_OBJECT_STR ||
            entry->val.type != MSGPACK_OBJECT_STR) {
            return -1;
        }

        if (set_tag_attribute(span, &entry->key, &entry->val,
                              parse_string_tags) != 0) {
            return -1;
        }
    }

    return set_span_status(span, tags);
}

static int set_span_annotations(struct ctrace_span *span,
                                msgpack_object *annotations)
{
    size_t index;
    uint64_t timestamp;
    msgpack_object *timestamp_object;
    msgpack_object *value;
    flb_sds_t name;

    if (annotations == NULL) {
        return 0;
    }
    if (annotations->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    for (index = 0; index < annotations->via.array.size; index++) {
        if (annotations->via.array.ptr[index].type != MSGPACK_OBJECT_MAP) {
            return -1;
        }

        timestamp_object = map_get(&annotations->via.array.ptr[index].via.map,
                                   "timestamp");
        value = map_get(&annotations->via.array.ptr[index].via.map, "value");
        if (object_get_uint64(timestamp_object, &timestamp) != 0 ||
            timestamp > UINT64_MAX / ZIPKIN_MICROSECONDS_TO_NANOSECONDS ||
            value == NULL || value->type != MSGPACK_OBJECT_STR) {
            return -1;
        }

        name = object_to_sds(value);
        if (name == NULL) {
            return -1;
        }

        if (ctr_span_event_add_ts(span, name,
                                  timestamp * ZIPKIN_MICROSECONDS_TO_NANOSECONDS) == NULL) {
            flb_sds_destroy(name);
            return -1;
        }
        flb_sds_destroy(name);
    }

    return 0;
}

static flb_sds_t scope_tag(msgpack_object *tags, const char *primary,
                           const char *legacy)
{
    msgpack_object *value;

    if (tags == NULL || tags->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    value = map_get(&tags->via.map, primary);
    if (value == NULL && legacy != NULL) {
        value = map_get(&tags->via.map, legacy);
    }

    return object_to_sds(value);
}

static int decode_span(struct ctrace *trace, msgpack_object *object,
                       int parse_string_tags)
{
    int ret;
    int same_parent;
    uint64_t duration;
    uint64_t start_time;
    uint64_t end_time;
    unsigned char trace_id[16];
    unsigned char span_id[8];
    unsigned char parent_id[8];
    msgpack_object *debug;
    msgpack_object *duration_object;
    msgpack_object *name_object;
    msgpack_object *parent_object;
    msgpack_object *shared;
    msgpack_object *tags;
    msgpack_object *timestamp_object;
    flb_sds_t name;
    flb_sds_t scope_name;
    flb_sds_t scope_version;
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span *scope_span;
    struct ctrace_instrumentation_scope *scope;
    struct ctrace_span *span;

    if (object->type != MSGPACK_OBJECT_MAP ||
        decode_identifier(map_get(&object->via.map, "traceId"),
                          trace_id, sizeof(trace_id), FLB_TRUE) != 0 ||
        decode_identifier(map_get(&object->via.map, "id"),
                          span_id, sizeof(span_id), FLB_FALSE) != 0) {
        return -1;
    }

    parent_object = map_get(&object->via.map, "parentId");
    if (parent_object != NULL &&
        decode_identifier(parent_object, parent_id, sizeof(parent_id), FLB_FALSE) != 0) {
        return -1;
    }

    name_object = map_get(&object->via.map, "name");
    if (name_object != NULL && name_object->type != MSGPACK_OBJECT_STR) {
        return -1;
    }
    name = name_object != NULL ? object_to_sds(name_object) : flb_sds_create("");
    if (name == NULL) {
        return -1;
    }

    tags = map_get(&object->via.map, "tags");
    if (tags != NULL && tags->type != MSGPACK_OBJECT_MAP) {
        flb_sds_destroy(name);
        return -1;
    }

    scope_name = scope_tag(tags, "otel.scope.name", "otel.library.name");
    scope_version = scope_tag(tags, "otel.scope.version", "otel.library.version");
    if (scope_name == NULL) {
        scope_name = flb_sds_create("zipkin");
    }

    resource_span = ctr_resource_span_create(trace);
    if (resource_span == NULL) {
        flb_sds_destroy(name);
        flb_sds_destroy(scope_name);
        flb_sds_destroy(scope_version);
        return -1;
    }
    scope_span = ctr_scope_span_create(resource_span);
    if (scope_span == NULL) {
        flb_sds_destroy(name);
        flb_sds_destroy(scope_name);
        flb_sds_destroy(scope_version);
        return -1;
    }

    scope = ctr_instrumentation_scope_create(scope_name, scope_version, 0, NULL);
    flb_sds_destroy(scope_name);
    flb_sds_destroy(scope_version);
    if (scope == NULL) {
        flb_sds_destroy(name);
        return -1;
    }
    ctr_scope_span_set_instrumentation_scope(scope_span, scope);

    span = ctr_span_create(trace, scope_span, name, NULL);
    flb_sds_destroy(name);
    if (span == NULL ||
        ctr_span_set_trace_id(span, trace_id, sizeof(trace_id)) != 0 ||
        ctr_span_set_span_id(span, span_id, sizeof(span_id)) != 0) {
        return -1;
    }

    same_parent = parent_object != NULL && memcmp(parent_id, span_id, sizeof(span_id)) == 0;
    if (parent_object != NULL && same_parent == FLB_FALSE &&
        ctr_span_set_parent_span_id(span, parent_id, sizeof(parent_id)) != 0) {
        return -1;
    }

    if (set_span_kind(span, map_get(&object->via.map, "kind")) != 0) {
        return -1;
    }

    timestamp_object = map_get(&object->via.map, "timestamp");
    if (timestamp_object == NULL) {
        start_time = 0;
        if (ctr_span_set_attribute_bool(span, "zipkin.start.time.absent", FLB_TRUE) != 0) {
            return -1;
        }
    }
    else if (object_get_uint64(timestamp_object, &start_time) != 0 ||
             start_time > UINT64_MAX / ZIPKIN_MICROSECONDS_TO_NANOSECONDS) {
        return -1;
    }
    else {
        start_time *= ZIPKIN_MICROSECONDS_TO_NANOSECONDS;
    }

    duration = 0;
    duration_object = map_get(&object->via.map, "duration");
    if (duration_object != NULL &&
        (object_get_uint64(duration_object, &duration) != 0 ||
         duration > UINT64_MAX / ZIPKIN_MICROSECONDS_TO_NANOSECONDS)) {
        return -1;
    }
    duration *= ZIPKIN_MICROSECONDS_TO_NANOSECONDS;
    if (UINT64_MAX - start_time < duration) {
        return -1;
    }
    end_time = start_time + duration;
    ctr_span_start_ts(trace, span, start_time);
    ctr_span_end_ts(trace, span, end_time);

    debug = map_get(&object->via.map, "debug");
    if (debug != NULL) {
        if (debug->type != MSGPACK_OBJECT_BOOLEAN) {
            return -1;
        }
        if (debug->via.boolean == true && ctr_span_set_flags(span, 1) != 0) {
            return -1;
        }
        if (ctr_span_set_attribute_bool(span, "zipkin.debug",
                                        debug->via.boolean == true) != 0) {
            return -1;
        }
    }

    shared = map_get(&object->via.map, "shared");
    if (shared != NULL) {
        if (shared->type != MSGPACK_OBJECT_BOOLEAN ||
            ctr_span_set_attribute_bool(span, "zipkin.shared",
                                        shared->via.boolean == true) != 0) {
            return -1;
        }
    }

    ret = set_endpoint_attributes(span, resource_span->resource,
                                  map_get(&object->via.map, "localEndpoint"), FLB_TRUE);
    if (ret == 0) {
        ret = set_endpoint_attributes(span, resource_span->resource,
                                      map_get(&object->via.map, "remoteEndpoint"), FLB_FALSE);
    }
    if (ret == 0) {
        ret = set_span_tags(span, tags, parse_string_tags);
    }
    if (ret == 0) {
        ret = set_span_annotations(span, map_get(&object->via.map, "annotations"));
    }

    return ret;
}

int zipkin_decode_json(const char *body, size_t body_size,
                       int parse_string_tags, struct ctrace **out_context,
                       size_t *out_span_count,
                       char error[ZIPKIN_DECODE_ERROR_SIZE])
{
    int ret;
    int root_type;
    size_t index;
    size_t packed_size;
    char *packed_buffer;
    struct ctrace *trace;
    msgpack_unpacked unpacked;

    *out_context = NULL;
    *out_span_count = 0;
    packed_buffer = NULL;

    ret = flb_pack_json(body, body_size, &packed_buffer, &packed_size,
                        &root_type, NULL);
    if (ret != 0 || root_type != JSMN_ARRAY) {
        flb_free(packed_buffer);
        set_error(error, SIZE_MAX, "payload must be a Zipkin v2 JSON array");
        return -1;
    }

    msgpack_unpacked_init(&unpacked);
    ret = msgpack_unpack_next(&unpacked, packed_buffer, packed_size, NULL);
    if (ret != MSGPACK_UNPACK_SUCCESS ||
        unpacked.data.type != MSGPACK_OBJECT_ARRAY) {
        msgpack_unpacked_destroy(&unpacked);
        flb_free(packed_buffer);
        set_error(error, SIZE_MAX, "could not decode JSON payload");
        return -1;
    }

    trace = ctr_create(NULL);
    if (trace == NULL) {
        msgpack_unpacked_destroy(&unpacked);
        flb_free(packed_buffer);
        set_error(error, SIZE_MAX, "could not allocate trace context");
        return -1;
    }

    for (index = 0; index < unpacked.data.via.array.size; index++) {
        ret = decode_span(trace, &unpacked.data.via.array.ptr[index],
                          parse_string_tags);
        if (ret != 0) {
            ctr_destroy(trace);
            msgpack_unpacked_destroy(&unpacked);
            flb_free(packed_buffer);
            set_error(error, index, "invalid Zipkin v2 span");
            return -1;
        }
    }

    *out_span_count = unpacked.data.via.array.size;
    *out_context = trace;
    msgpack_unpacked_destroy(&unpacked);
    flb_free(packed_buffer);

    return 0;
}
