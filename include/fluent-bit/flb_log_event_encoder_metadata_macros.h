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

#ifndef FLB_LOG_EVENT_ENCODER_METADATA_MACROS_H
#define FLB_LOG_EVENT_ENCODER_METADATA_MACROS_H

#define flb_log_event_encoder_append_metadata_binary_length(context, length) \
            flb_log_event_encoder_append_binary_length(context, FLB_LOG_EVENT_METADATA, length)

#define flb_log_event_encoder_append_metadata_binary_body(context, value, length) \
            flb_log_event_encoder_append_binary_body(context, FLB_LOG_EVENT_METADATA, value, length)

#define flb_log_event_encoder_append_metadata_ext_length(context, type, length) \
            flb_log_event_encoder_append_ext_length(context, FLB_LOG_EVENT_METADATA, type, length)

#define flb_log_event_encoder_append_metadata_ext_body(context, value, length) \
            flb_log_event_encoder_append_ext_body(context, FLB_LOG_EVENT_METADATA, value, length)

#define flb_log_event_encoder_append_metadata_string_length(context, length) \
            flb_log_event_encoder_append_string_length(context, FLB_LOG_EVENT_METADATA, length)

#define flb_log_event_encoder_append_metadata_string_body(context, value, length) \
            flb_log_event_encoder_append_string_body(context, FLB_LOG_EVENT_METADATA, value, length)

#define flb_log_event_encoder_append_metadata_int8(context, value) \
            flb_log_event_encoder_append_int8(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_int16(context, value) \
            flb_log_event_encoder_append_int16(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_int32(context, value) \
            flb_log_event_encoder_append_int32(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_int64(context, value) \
            flb_log_event_encoder_append_int64(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_uint8(context, value) \
            flb_log_event_encoder_append_uint8(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_uint16(context, value) \
            flb_log_event_encoder_append_uint16(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_uint32(context, value) \
            flb_log_event_encoder_append_uint32(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_uint64(context, value) \
            flb_log_event_encoder_append_uint64(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_double(context, value) \
            flb_log_event_encoder_append_double(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_boolean(context, value) \
            flb_log_event_encoder_append_boolean(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_character(context, value) \
            flb_log_event_encoder_append_character(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_binary(context, value, length) \
            flb_log_event_encoder_append_binary(context, FLB_LOG_EVENT_METADATA, value, length)

#define flb_log_event_encoder_append_metadata_string(context, value, length) \
            flb_log_event_encoder_append_string(context, FLB_LOG_EVENT_METADATA, value, length)

#define flb_log_event_encoder_append_metadata_ext(context, type, value, length) \
            flb_log_event_encoder_append_ext(context, FLB_LOG_EVENT_METADATA, type, value, length)

#define flb_log_event_encoder_append_metadata_cstring(context, value) \
            flb_log_event_encoder_append_cstring(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_null(context) \
            flb_log_event_encoder_append_null(context, FLB_LOG_EVENT_METADATA)

#define flb_log_event_encoder_append_metadata_msgpack_object(context, value) \
            flb_log_event_encoder_append_msgpack_object(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_raw_msgpack(context, value_buffer, value_size) \
            flb_log_event_encoder_append_raw_msgpack(context, FLB_LOG_EVENT_METADATA, value_buffer, value_size)

#define flb_log_event_encoder_append_metadata_timestamp(context, value) \
            flb_log_event_encoder_append_timestamp(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_legacy_timestamp(context, value) \
            flb_log_event_encoder_append_legacy_timestamp(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_forward_v1_timestamp(context, value) \
            flb_log_event_encoder_append_forward_v1_timestamp(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_fluent_bit_v1_timestamp(context, value) \
            flb_log_event_encoder_append_fluent_bit_v1_timestamp(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_append_metadata_fluent_bit_v2_timestamp(context, value) \
            flb_log_event_encoder_append_fluent_bit_v2_timestamp(context, FLB_LOG_EVENT_METADATA, value)

#define flb_log_event_encoder_metadata_begin_map(context) \
            flb_log_event_encoder_dynamic_field_begin_map(&(context->metadata))

#define flb_log_event_encoder_metadata_commit_map(context) \
            flb_log_event_encoder_dynamic_field_commit_map(&(context->metadata))

#define flb_log_event_encoder_metadata_rollback_map(context) \
            flb_log_event_encoder_dynamic_field_rollback_map(&(context->metadata))

#define flb_log_event_encoder_metadata_begin_array(context) \
            flb_log_event_encoder_dynamic_field_begin_array(&(context->metadata))

#define flb_log_event_encoder_metadata_commit_array(context) \
            flb_log_event_encoder_dynamic_field_commit_array(&(context->metadata))

#define flb_log_event_encoder_metadata_rollback_array(context) \
            flb_log_event_encoder_dynamic_field_rollback_array(&(context->metadata))

static inline \
int flb_log_event_encoder_set_metadata_from_msgpack_object(
        struct flb_log_event_encoder *context,
        msgpack_object *value)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_metadata_msgpack_object(
                    context, value);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_flush(&context->metadata);
    }

    return result;
}

static inline \
int flb_log_event_encoder_set_metadata_from_raw_msgpack(
    struct flb_log_event_encoder *context,
    char *value_buffer,
    size_t value_size)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_metadata_raw_msgpack(
                    context,
                    value_buffer,
                    value_size);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_flush(&context->metadata);
    }

    return result;
}

#endif