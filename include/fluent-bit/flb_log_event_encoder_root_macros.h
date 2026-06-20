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

#ifndef FLB_LOG_EVENT_ENCODER_ROOT_MACROS_H
#define FLB_LOG_EVENT_ENCODER_ROOT_MACROS_H

#define flb_log_event_encoder_append_root_binary_length(context, length) \
            flb_log_event_encoder_append_binary_length(context, FLB_LOG_EVENT_ROOT, length)

#define flb_log_event_encoder_append_root_binary_body(context, value, length) \
            flb_log_event_encoder_append_binary_body(context, FLB_LOG_EVENT_ROOT, value, length)

#define flb_log_event_encoder_append_root_ext_length(context, type, length) \
            flb_log_event_encoder_append_ext_length(context, FLB_LOG_EVENT_ROOT, type, length)

#define flb_log_event_encoder_append_root_ext_body(context, value, length) \
            flb_log_event_encoder_append_ext_body(context, FLB_LOG_EVENT_ROOT, value, length)

#define flb_log_event_encoder_append_root_string_length(context, length) \
            flb_log_event_encoder_append_string_length(context, FLB_LOG_EVENT_ROOT, length)

#define flb_log_event_encoder_append_root_string_body(context, value, length) \
            flb_log_event_encoder_append_string_body(context, FLB_LOG_EVENT_ROOT, value, length)

#define flb_log_event_encoder_append_root_int8(context, value) \
            flb_log_event_encoder_append_int8(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_int16(context, value) \
            flb_log_event_encoder_append_int16(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_int32(context, value) \
            flb_log_event_encoder_append_int32(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_int64(context, value) \
            flb_log_event_encoder_append_int64(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_uint8(context, value) \
            flb_log_event_encoder_append_uint8(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_uint16(context, value) \
            flb_log_event_encoder_append_uint16(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_uint32(context, value) \
            flb_log_event_encoder_append_uint32(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_uint64(context, value) \
            flb_log_event_encoder_append_uint64(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_double(context, value) \
            flb_log_event_encoder_append_double(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_boolean(context, value) \
            flb_log_event_encoder_append_boolean(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_character(context, value) \
            flb_log_event_encoder_append_character(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_binary(context, value, length) \
            flb_log_event_encoder_append_binary(context, FLB_LOG_EVENT_ROOT, value, length)

#define flb_log_event_encoder_append_root_string(context, value, length) \
            flb_log_event_encoder_append_string(context, FLB_LOG_EVENT_ROOT, value, length)

#define flb_log_event_encoder_append_root_ext(context, type, value, length) \
            flb_log_event_encoder_append_ext(context, FLB_LOG_EVENT_ROOT, type, value, length)

#define flb_log_event_encoder_append_root_cstring(context, value) \
            flb_log_event_encoder_append_cstring(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_null(context) \
            flb_log_event_encoder_append_null(context, FLB_LOG_EVENT_ROOT)

#define flb_log_event_encoder_append_root_msgpack_object(context, value) \
            flb_log_event_encoder_append_msgpack_object(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_raw_msgpack(context, value_buffer, value_size) \
            flb_log_event_encoder_append_raw_msgpack(context, FLB_LOG_EVENT_ROOT, value_buffer, value_size)

#define flb_log_event_encoder_append_root_timestamp(context, value) \
            flb_log_event_encoder_append_timestamp(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_legacy_timestamp(context, value) \
            flb_log_event_encoder_append_legacy_timestamp(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_forward_v1_timestamp(context, value) \
            flb_log_event_encoder_append_forward_v1_timestamp(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_fluent_bit_v1_timestamp(context, value) \
            flb_log_event_encoder_append_fluent_bit_v1_timestamp(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_append_root_fluent_bit_v2_timestamp(context, value) \
            flb_log_event_encoder_append_fluent_bit_v2_timestamp(context, FLB_LOG_EVENT_ROOT, value)

#define flb_log_event_encoder_root_begin_map(context) \
            flb_log_event_encoder_dynamic_field_begin_map(&(context->root))

#define flb_log_event_encoder_root_commit_map(context) \
            flb_log_event_encoder_dynamic_field_commit_map(&(context->root))

#define flb_log_event_encoder_root_rollback_map(context) \
            flb_log_event_encoder_dynamic_field_rollback_map(&(context->root))

#define flb_log_event_encoder_root_begin_array(context) \
            flb_log_event_encoder_dynamic_field_begin_array(&(context->root))

#define flb_log_event_encoder_root_commit_array(context) \
            flb_log_event_encoder_dynamic_field_commit_array(&(context->root))

#define flb_log_event_encoder_root_rollback_array(context) \
            flb_log_event_encoder_dynamic_field_rollback_array(&(context->root))


static inline \
int flb_log_event_encoder_set_root_from_msgpack_object(
        struct flb_log_event_encoder *context,
        msgpack_object *value)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_reset(&context->body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_reset(&context->root);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_root_msgpack_object(
                    context, value);

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_log_event_encoder_dynamic_field_flush(&context->root);
        }
    }

    return result;
}

static inline \
int flb_log_event_encoder_set_root_from_raw_msgpack(
        struct flb_log_event_encoder *context,
        char *value_buffer,
        size_t value_size)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_reset(&context->body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_reset(&context->root);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_root_raw_msgpack(
                    context,
                    value_buffer,
                    value_size);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_flush(&context->root);
    }

    return result;
}

#endif