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

#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_byteswap.h>

void flb_log_event_encoder_reset(struct flb_log_event_encoder *context)
{
    msgpack_sbuffer_clear(&context->buffer);
}

int flb_log_event_encoder_init(struct flb_log_event_encoder *context, int format)
{
    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (format < FLB_LOG_EVENT_FORMAT_FORWARD ||
        format > FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    memset(context, 0, sizeof(struct flb_log_event_encoder));

    context->dynamically_allocated = FLB_FALSE;
    context->format = format;

    msgpack_sbuffer_init(&context->buffer);
    msgpack_packer_init(&context->packer,
                        &context->buffer,
                        msgpack_sbuffer_write);

    flb_log_event_encoder_dynamic_field_init(&context->metadata,
                                             MSGPACK_OBJECT_MAP);

    flb_log_event_encoder_dynamic_field_init(&context->body,
                                             MSGPACK_OBJECT_MAP);

    return FLB_EVENT_ENCODER_SUCCESS;
}

struct flb_log_event_encoder *flb_log_event_encoder_create(int format)
{
    struct flb_log_event_encoder *context;
    int                           result;

    context = (struct flb_log_event_encoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_encoder));

    result = flb_log_event_encoder_init(context, format);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        context->dynamically_allocated = FLB_TRUE;
    }
    else if (context != NULL) {
        flb_log_event_encoder_destroy(context);

        context = NULL;
    }

    return context;
}

void static inline flb_log_event_encoder_update_internal_state(
    struct flb_log_event_encoder *context)
{
    context->output_buffer = context->buffer.data;
    context->output_length = context->buffer.size;
}

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context)
{
    if (context != NULL) {
        flb_log_event_encoder_dynamic_field_destroy(&context->metadata);
        flb_log_event_encoder_dynamic_field_destroy(&context->body);

        msgpack_sbuffer_destroy(&context->buffer);

        if (context->dynamically_allocated) {
            flb_free(context);
        }
    }
}

void flb_log_event_encoder_claim_internal_buffer_ownership(
        struct flb_log_event_encoder *context)
{
    if (context != NULL) {
        msgpack_sbuffer_release(&context->buffer);
    }
}

static int flb_log_event_encoder_pack_legacy_timestamp(
    struct flb_log_event_encoder *context,
    struct flb_time *timestamp)
{
    int result;

    result = msgpack_pack_uint64(&context->packer, timestamp->tm.tv_sec);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

static int flb_log_event_encoder_pack_forward_v1_timestamp(
    struct flb_log_event_encoder *context,
    struct flb_time *timestamp)
{
    uint32_t components[2];
    int      result;

    components[0] = FLB_BSWAP_32((uint32_t) timestamp->tm.tv_sec);
    components[1] = FLB_BSWAP_32((uint32_t) timestamp->tm.tv_nsec);

    result = msgpack_pack_ext(&context->packer, 8, 0);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    result = msgpack_pack_ext_body(&context->packer,
                                   components,
                                   sizeof(components));

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

static int flb_log_event_encoder_pack_fluent_bit_v2_timestamp(
    struct flb_log_event_encoder *context,
    struct flb_time *timestamp)
{
    return flb_log_event_encoder_pack_forward_v1_timestamp(context, timestamp);
}

int flb_log_event_encoder_pack_timestamp(struct flb_log_event_encoder *context,
                                         struct flb_time *timestamp)
{
    struct flb_time current_timestamp;
    int             result;

    if (timestamp == NULL) {
        flb_time_get(&current_timestamp);

        timestamp = &current_timestamp;
    }

    if (context->format == FLB_LOG_EVENT_FORMAT_FORWARD_LEGACY) {
        result = flb_log_event_encoder_pack_legacy_timestamp(context,
                                                             timestamp);
    }
    else if (context->format == FLB_LOG_EVENT_FORMAT_FORWARD) {
        result = flb_log_event_encoder_pack_forward_v1_timestamp(context,
                                                                 timestamp);
    }
    else if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
        result = flb_log_event_encoder_pack_fluent_bit_v2_timestamp(context,
                                                                    timestamp);
    }
    else {
        result = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_update_internal_state(context);
    }

    return result;
}

int flb_log_event_encoder_pack_empty_object(struct flb_log_event_encoder *context,
                                            int object_type)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (object_type == MSGPACK_OBJECT_MAP) {
        result = msgpack_pack_map(&context->packer, 0);

        if (result != 0) {
            result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
        }
        else {
            result = FLB_EVENT_ENCODER_SUCCESS;
        }
    }
    else if (object_type == MSGPACK_OBJECT_ARRAY) {
        result = msgpack_pack_array(&context->packer, 0);

        if (result != 0) {
            result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
        }
        else {
            result = FLB_EVENT_ENCODER_SUCCESS;
        }
    }
    else {
        result = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_update_internal_state(context);
    }

    return result;
}

int flb_log_event_encoder_pack_msgpack_object_or_empty_object(
    struct flb_log_event_encoder *context,
    msgpack_object *object,
    int placeholder_type)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (object == NULL) {
        result = flb_log_event_encoder_pack_empty_object(context,
                                                         placeholder_type);
    }
    else {
        result = flb_log_event_encoder_pack_msgpack_object(context,
                                                           object);

        if (result != 0) {
            result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
        }
        else {
            result = FLB_EVENT_ENCODER_SUCCESS;
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_update_internal_state(context);
    }

    return result;
}

int flb_log_event_encoder_pack_raw_msgpack_or_empty_object(
    struct flb_log_event_encoder *context,
    const char *buffer,
    size_t length,
    int placeholder_type)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (buffer == NULL) {
        result = flb_log_event_encoder_pack_empty_object(context, placeholder_type);
    }
    else {
        result = flb_log_event_encoder_pack_msgpack_raw_buffer(context,
                                                               buffer,
                                                               length);

        if (result != 0) {
            result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
        }
        else {
            result = FLB_EVENT_ENCODER_SUCCESS;
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_update_internal_state(context);
    }

    return result;
}

int flb_log_event_encoder_pack_array(struct flb_log_event_encoder *context,
                                     size_t element_count)
{
    if (msgpack_pack_array(&context->packer, element_count) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_map(struct flb_log_event_encoder *context,
                                   size_t element_count)
{
    if (msgpack_pack_map(&context->packer, element_count) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}


int flb_log_event_encoder_pack_string_length(
    struct flb_log_event_encoder *context,
    size_t length)
{
    if (msgpack_pack_str(&context->packer, length) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_string_body(
    struct flb_log_event_encoder *context,
    char *value,
    size_t length)
{
    if (msgpack_pack_str_body(&context->packer, value, length) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_string_with_length(
    struct flb_log_event_encoder *context,
    char *value,
    size_t length)
{
    if (msgpack_pack_str_with_body(&context->packer, value, length) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_string(
    struct flb_log_event_encoder *context,
    char *value)
{
    return flb_log_event_encoder_pack_string_with_length(context,
                                                         value,
                                                         strlen(value));
}

int flb_log_event_encoder_pack_flb_sds(
    struct flb_log_event_encoder *context,
    flb_sds_t value)
{
    return flb_log_event_encoder_pack_string_with_length(context,
                                                         (char *) value,
                                                         flb_sds_len(value));
}

int flb_log_event_encoder_pack_uint64(
    struct flb_log_event_encoder *context,
    uint64_t value)
{
    if (msgpack_pack_uint64(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_uint32(
    struct flb_log_event_encoder *context,
    uint32_t value)
{
    if (msgpack_pack_uint32(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_uint16(
    struct flb_log_event_encoder *context,
    uint16_t value)
{
    if (msgpack_pack_uint16(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_uint8(
    struct flb_log_event_encoder *context,
    uint8_t value)
{
    if (msgpack_pack_uint8(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_int64(
    struct flb_log_event_encoder *context,
    int64_t value)
{
    if (msgpack_pack_int64(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_int32(
    struct flb_log_event_encoder *context,
    int32_t value)
{
    if (msgpack_pack_int32(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_int16(
    struct flb_log_event_encoder *context,
    int16_t value)
{
    if (msgpack_pack_int16(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_int8(
    struct flb_log_event_encoder *context,
    int8_t value)
{
    if (msgpack_pack_int8(&context->packer, value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_raw_msgpack(
    struct flb_log_event_encoder *context,
    char *value,
    size_t length)
{
    if (msgpack_pack_str_body(&context->packer, value, length) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_produce_timestamp(
    struct flb_log_event_encoder *context,
    struct flb_time *timestamp)
{
    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (timestamp == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    return flb_log_event_encoder_pack_timestamp(context, timestamp);
}

int flb_log_event_encoder_pack_msgpack_object(struct flb_log_event_encoder *context,
                                              msgpack_object *value)
{
    int result;

    result = msgpack_pack_object(&context->packer, *value);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_pack_msgpack_raw_buffer(struct flb_log_event_encoder *context,
                                                  const char *buffer,
                                                  size_t length)
{
    int result;

    result = msgpack_pack_str_body(&context->packer, buffer, length);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

static int flb_log_event_encoder_produce_current_timestamp(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    struct flb_time timestamp;

    /* This result is not verified because _flb_time_get
     * does not standardize the result value so it's not
     * properly predictable.
     */

    flb_time_get(&timestamp);

    return flb_log_event_encoder_produce_timestamp(context, &timestamp);
}

static int flb_log_event_encoder_produce_empty_metadata(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    return flb_log_event_encoder_pack_empty_object(context, MSGPACK_OBJECT_MAP);
}

static int flb_log_event_encoder_produce_empty_body(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    return flb_log_event_encoder_pack_empty_object(context, MSGPACK_OBJECT_MAP);
}


int flb_log_event_encoder_append(struct flb_log_event_encoder *context,
                                 flb_event_encoder_callback timestamp_callback,
                                 flb_event_encoder_callback metadata_callback,
                                 flb_event_encoder_callback body_callback,
                                 void *user_data)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (timestamp_callback == NULL) {
        timestamp_callback = flb_log_event_encoder_produce_current_timestamp;
    }

    if (metadata_callback == NULL) {
        metadata_callback = flb_log_event_encoder_produce_empty_metadata;
    }

    if (body_callback == NULL) {
        body_callback = flb_log_event_encoder_produce_empty_body;
    }

    /* outermost array */
    result = msgpack_pack_array(&context->packer, 2);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
        result = msgpack_pack_array(&context->packer, 2);

        if (result != 0) {
            return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
        }
    }

    result = timestamp_callback(context, user_data);

    if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = metadata_callback(context, user_data);
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = body_callback(context, user_data);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_update_internal_state(context);
    }

    return result;
}

static int flb_log_event_encoder_produce_msgpack_component_timestamp(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    struct flb_log_event_encoder_msgpack_components *components;
    int                                              result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    components = (struct flb_log_event_encoder_msgpack_components *) \
        user_data;

    if (components == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    if (components->timestamp == NULL) {
        result = flb_log_event_encoder_produce_current_timestamp(
                    context, NULL);
    }
    else {
        result = flb_log_event_encoder_produce_timestamp(
                    context,
                    components->timestamp);
    }

    return result;
}

static int flb_log_event_encoder_produce_msgpack_component_metadata(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    struct flb_log_event_encoder_msgpack_components *components;
    int                                              result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    components = (struct flb_log_event_encoder_msgpack_components *) \
        user_data;

    if (components == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_log_event_encoder_pack_msgpack_object_or_empty_object(
                context,
                components->metadata,
                MSGPACK_OBJECT_MAP);

    return result;
}

static int flb_log_event_encoder_produce_msgpack_component_body(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    struct flb_log_event_encoder_msgpack_components *components;
    int                                              result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    components = (struct flb_log_event_encoder_msgpack_components *) \
        user_data;

    if (components == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_log_event_encoder_pack_msgpack_object_or_empty_object(
                context,
                components->body,
                MSGPACK_OBJECT_MAP);

    return result;
}

int flb_log_event_encoder_append_msgpack_object(
        struct flb_log_event_encoder *context,
        struct flb_time *timestamp,
        msgpack_object *metadata,
        msgpack_object *body)

{
    struct flb_log_event_encoder_msgpack_components components;

    components.timestamp = timestamp;
    components.metadata = metadata;
    components.body = body;

    return flb_log_event_encoder_append(
                context,
                flb_log_event_encoder_produce_msgpack_component_timestamp,
                flb_log_event_encoder_produce_msgpack_component_metadata,
                flb_log_event_encoder_produce_msgpack_component_body,
                (void *) &components);
}

static int flb_log_event_encoder_produce_raw_msgpack_component_timestamp(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    struct flb_log_event_encoder_raw_msgpack_components *components;
    int                                                  result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    components = (struct flb_log_event_encoder_raw_msgpack_components *) \
                    user_data;

    if (components == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    if (components->timestamp == NULL) {
        result = flb_log_event_encoder_produce_current_timestamp(
                    context, NULL);
    }
    else {
        result = flb_log_event_encoder_produce_timestamp(
                    context,
                    components->timestamp);
    }

    return result;
}

static int flb_log_event_encoder_produce_raw_msgpack_component_metadata(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    struct flb_log_event_encoder_raw_msgpack_components *components;
    int                                                  result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    components = (struct flb_log_event_encoder_raw_msgpack_components *) \
        user_data;

    if (components == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_log_event_encoder_pack_raw_msgpack_or_empty_object(
                context,
                components->metadata_buffer,
                components->metadata_length,
                MSGPACK_OBJECT_MAP);

    return result;
}

static int flb_log_event_encoder_produce_raw_msgpack_component_body(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    struct flb_log_event_encoder_raw_msgpack_components *components;
    int                                                  result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    components = (struct flb_log_event_encoder_raw_msgpack_components *) \
                    user_data;

    if (components == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_log_event_encoder_pack_raw_msgpack_or_empty_object(
                context,
                components->body_buffer,
                components->body_length,
                MSGPACK_OBJECT_MAP);

    return result;
}

int flb_log_event_encoder_append_msgpack_raw(
        struct flb_log_event_encoder *context,
        struct flb_time *timestamp,
        const char *metadata_buffer,
        size_t metadata_length,
        const char *body_buffer,
        size_t body_length)
{
    struct flb_log_event_encoder_raw_msgpack_components components;

    components.metadata_buffer = metadata_buffer;
    components.metadata_length = metadata_length;
    components.body_buffer = body_buffer;
    components.body_length = body_length;
    components.timestamp = timestamp;

    return flb_log_event_encoder_append(
                context,
                flb_log_event_encoder_produce_raw_msgpack_component_timestamp,
                flb_log_event_encoder_produce_raw_msgpack_component_metadata,
                flb_log_event_encoder_produce_raw_msgpack_component_body,
                (void *) &components);
}

int flb_log_event_encoder_record_reset(struct flb_log_event_encoder *context)
{
    flb_log_event_encoder_dynamic_field_reset(&context->metadata);
    flb_log_event_encoder_dynamic_field_reset(&context->body);

    flb_log_event_encoder_record_metadata_start_map(context);
    flb_log_event_encoder_record_body_start_map(context);

    flb_time_zero(&context->timestamp);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_rollback(struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_record_reset(context);
}

int flb_log_event_encoder_record_start(struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_record_reset(context);
}

int flb_log_event_encoder_record_commit(struct flb_log_event_encoder *context)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_flush(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_flush(&context->body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_msgpack_raw(
                    context,
                    &context->timestamp,
                    context->metadata.data,
                    context->metadata.size,
                    context->body.data,
                    context->body.size);
    }

    flb_log_event_encoder_record_reset(context);

    return result;
}

int flb_log_event_encoder_record_timestamp_set(
        struct flb_log_event_encoder *context,
        struct flb_time *timestamp)
{
    if (timestamp != NULL) {
        flb_time_copy(&context->timestamp, timestamp);
    }
    else {
        flb_time_get(&context->timestamp);
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_metadata_set_msgpack_object(
        struct flb_log_event_encoder *context,
        msgpack_object *value)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_record_metadata_append_msgpack_object(
                    context, value);
    }

    return result;
}

int flb_log_event_encoder_record_metadata_set_msgpack_raw(
    struct flb_log_event_encoder *context,
    char *value_buffer,
    size_t value_size)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_record_metadata_append_msgpack_raw(
                    context,
                    value_buffer,
                    value_size);
    }

    return result;
}

int flb_log_event_encoder_record_metadata_append_string(
    struct flb_log_event_encoder *context,
    char *value)
{
    flb_log_event_encoder_dynamic_field_append(&context->metadata);

    if (msgpack_pack_str_with_body(&context->metadata.packer,
                                   value,
                                   strlen(value)) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_metadata_append_msgpack_object(
    struct flb_log_event_encoder *context,
    msgpack_object *value)
{
    flb_log_event_encoder_dynamic_field_append(&context->metadata);

    if (msgpack_pack_object(&context->metadata.packer,
                            *value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_metadata_append_msgpack_raw(
    struct flb_log_event_encoder *context,
    char *value_buffer,
    size_t value_size)
{
    flb_log_event_encoder_dynamic_field_append(&context->metadata);

    if (msgpack_pack_str_body(&context->metadata.packer,
                              value_buffer,
                              value_size) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_metadata_start_map(
        struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_start_map(
                &context->metadata);
}

int flb_log_event_encoder_record_metadata_commit_map(
        struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_commit_map(
                &context->metadata);
}

int flb_log_event_encoder_record_metadata_rollback_map(
        struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_rollback_map(
                &context->metadata);
}

int flb_log_event_encoder_record_metadata_start_array(
        struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_start_array(
                &context->metadata);
}

int flb_log_event_encoder_record_metadata_commit_array(
        struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_commit_array(
                &context->metadata);
}

int flb_log_event_encoder_record_metadata_rollback_array(
        struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_rollback_array(
                &context->metadata);
}

int flb_log_event_encoder_record_body_set_msgpack_object(
        struct flb_log_event_encoder *context,
        msgpack_object *value)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->body);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_record_body_append_msgpack_object(context, value);
    }

    return result;
}

int flb_log_event_encoder_record_body_set_msgpack_raw(
        struct flb_log_event_encoder *context,
        char *value_buffer,
        size_t value_size)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_reset(&context->body);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_record_body_append_msgpack_raw(context,
                                                                      value_buffer,
                                                                      value_size);
    }

    return result;
}

int flb_log_event_encoder_record_body_append_string(
        struct flb_log_event_encoder *context,
        char *value)
{
    flb_log_event_encoder_dynamic_field_append(&context->body);

    if (msgpack_pack_str_with_body(&context->body.packer,
                                   value,
                                   strlen(value)) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_body_append_uint64(
        struct flb_log_event_encoder *context,
        uint64_t value)
{
    flb_log_event_encoder_dynamic_field_append(&context->body);

    if (msgpack_pack_uint64(&context->body.packer,
                            value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_body_append_msgpack_object(
    struct flb_log_event_encoder *context,
    msgpack_object *value)
{
    flb_log_event_encoder_dynamic_field_append(&context->body);

    if (msgpack_pack_object(&context->body.packer,
                            *value) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_body_append_msgpack_raw(
        struct flb_log_event_encoder *context,
        char *value_buffer,
        size_t value_size)
{
    flb_log_event_encoder_dynamic_field_append(&context->body);

    if (msgpack_pack_str_body(&context->body.packer,
                              value_buffer,
                              value_size) != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_record_body_start_map(
    struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_start_map(&context->body);
}

int flb_log_event_encoder_record_body_commit_map(
    struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_commit_map(&context->body);
}

int flb_log_event_encoder_record_body_rollback_map(
    struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_rollback_map(&context->body);
}

int flb_log_event_encoder_record_body_start_array(
    struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_start_array(&context->body);
}

int flb_log_event_encoder_record_body_commit_array(
    struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_commit_array(&context->body);
}

int flb_log_event_encoder_record_body_rollback_array(
    struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_dynamic_field_rollback_array(&context->body);
}

struct flb_log_event_encoder_dynamic_field_scope *
    flb_log_event_encoder_dynamic_field_scope_current(
    struct flb_log_event_encoder_dynamic_field *field)
{
    if (cfl_list_is_empty(&field->scopes)) {
        return NULL;
    }

    return cfl_list_entry_first(
                &field->scopes,
                struct flb_log_event_encoder_dynamic_field_scope,
                _head);
}

int flb_log_event_encoder_dynamic_field_scope_enter(
    struct flb_log_event_encoder_dynamic_field *field,
    int type)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    if (type != MSGPACK_OBJECT_MAP &&
        type == MSGPACK_OBJECT_ARRAY) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    scope = flb_calloc(1,
                       sizeof(struct flb_log_event_encoder_dynamic_field_scope));

    if (scope == NULL) {
        return FLB_EVENT_ENCODER_ERROR_ALLOCATION_ERROR;
    }

    cfl_list_entry_init(&scope->_head);

    scope->type = type;
    scope->offset = field->buffer.size;

    cfl_list_prepend(&scope->_head, &field->scopes);

    if (type == MSGPACK_OBJECT_MAP) {
        flb_mp_map_header_init(&scope->header, &field->packer);
    }
    else if (type == MSGPACK_OBJECT_ARRAY) {
        flb_mp_array_header_init(&scope->header, &field->packer);
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_dynamic_field_scope_leave(
    struct flb_log_event_encoder_dynamic_field *field,
    struct flb_log_event_encoder_dynamic_field_scope *scope,
    int commit)
{
    if (scope == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    if (commit) {
        /* We increment the entry count on each append because
         * we don't discriminate based on the scope type so
         * we need to divide the entry count by two for maps
         * to ensure the entry count matches the kv pair count
         */

        if (field->type == MSGPACK_OBJECT_MAP) {
            scope->header.entries /= 2;
        }

        flb_mp_map_header_end(&scope->header);
    }
    else {
        field->buffer.size = scope->offset;
    }

    cfl_list_del(&scope->_head);

    flb_free(scope);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_dynamic_field_start_map(
    struct flb_log_event_encoder_dynamic_field *field)
{
    return flb_log_event_encoder_dynamic_field_scope_enter(field,
                                                           MSGPACK_OBJECT_MAP);
}

int flb_log_event_encoder_dynamic_field_start_array(
    struct flb_log_event_encoder_dynamic_field *field)
{
    return flb_log_event_encoder_dynamic_field_scope_enter(field,
                                                           MSGPACK_OBJECT_ARRAY);
}

int flb_log_event_encoder_dynamic_field_commit_map(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_TRUE);
}

int flb_log_event_encoder_dynamic_field_commit_array(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_TRUE);
}

int flb_log_event_encoder_dynamic_field_rollback_map(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_FALSE);
}

int flb_log_event_encoder_dynamic_field_rollback_array(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    return flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                           scope,
                                                           FLB_TRUE);
}

int flb_log_event_encoder_dynamic_field_append(
    struct flb_log_event_encoder_dynamic_field *field)
{
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    scope = flb_log_event_encoder_dynamic_field_scope_current(field);

    if (scope == NULL) {
        if (cfl_list_is_empty(&field->scopes)) {
            return FLB_EVENT_ENCODER_SUCCESS;
        }

        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    flb_mp_map_header_append(&scope->header);

    return FLB_EVENT_ENCODER_SUCCESS;
}


static int flb_log_event_encoder_dynamic_field_flush_scopes(
    struct flb_log_event_encoder_dynamic_field *field,
    int commit)
{
    int                                               result;
    struct flb_log_event_encoder_dynamic_field_scope *scope;

    result = FLB_EVENT_ENCODER_SUCCESS;

    do {
        scope = flb_log_event_encoder_dynamic_field_scope_current(field);

        if (scope != NULL) {
            result = flb_log_event_encoder_dynamic_field_scope_leave(field,
                                                                     scope,
                                                                     commit);
        }
    } while (scope != NULL &&
             result == FLB_EVENT_ENCODER_SUCCESS);

    return result;
}

int flb_log_event_encoder_dynamic_field_flush(
    struct flb_log_event_encoder_dynamic_field *field)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_flush_scopes(field, FLB_TRUE);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        field->data = field->buffer.data;
        field->size = field->buffer.size;
    }

    return result;
}

int flb_log_event_encoder_dynamic_field_reset(
    struct flb_log_event_encoder_dynamic_field *field)
{
    msgpack_sbuffer_clear(&field->buffer);

    flb_log_event_encoder_dynamic_field_flush_scopes(field, FLB_FALSE);

    field->data = NULL;
    field->size = 0;

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_dynamic_field_init(
    struct flb_log_event_encoder_dynamic_field *field,
    int type)
{
    msgpack_sbuffer_init(&field->buffer);
    msgpack_packer_init(&field->packer,
                        &field->buffer,
                        msgpack_sbuffer_write);

    field->initialized = FLB_TRUE;
    field->type = type;

    cfl_list_init(&field->scopes);
    flb_log_event_encoder_dynamic_field_reset(field);

    return FLB_EVENT_ENCODER_SUCCESS;
}

void flb_log_event_encoder_dynamic_field_destroy(
    struct flb_log_event_encoder_dynamic_field *field)
{
    msgpack_sbuffer_destroy(&field->buffer);

    field->initialized = FLB_FALSE;
}
