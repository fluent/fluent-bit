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

static int create_empty_map(struct flb_log_event_decoder *context) {
    msgpack_packer  packer;
    msgpack_sbuffer buffer;
    int             result;
    size_t          offset;

    result = FLB_EVENT_DECODER_SUCCESS;

    context->empty_map = NULL;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    result = msgpack_pack_map(&packer, 0);

    if (result != 0) {
        result = FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE;
    }
    else {
        offset = 0;

        result = msgpack_unpack_next(&context->unpacked_empty_map,
                                     buffer.data,
                                     buffer.size,
                                     &offset);

        if (result != MSGPACK_UNPACK_SUCCESS) {
            result = FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE;
        }
        else {
            context->empty_map = &context->unpacked_empty_map.data;

            result = FLB_EVENT_DECODER_SUCCESS;
        }
    }

    msgpack_sbuffer_destroy(&buffer);

    return result;
}

struct flb_log_event_decoder *flb_log_event_decoder_create(
    const char *input_buffer,
    size_t input_length)
{
    struct flb_log_event_decoder *context;
    int                           result;

    context = (struct flb_log_event_decoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_decoder));

    if (context != NULL) {
        msgpack_unpacked_init(&context->unpacked_empty_map);
        msgpack_unpacked_init(&context->unpacked_event);

        result = create_empty_map(context);

        if (result == FLB_EVENT_DECODER_SUCCESS) {
            context->buffer = input_buffer;
            context->length = input_length;
        }
        else {
            flb_log_event_decoder_destroy(context);

            context = NULL;
        }
    }

    return context;
}

void flb_log_event_decoder_destroy(struct flb_log_event_decoder *context)
{
    if (context != NULL) {
        msgpack_unpacked_destroy(&context->unpacked_empty_map);
        msgpack_unpacked_destroy(&context->unpacked_event);

        free(context);
    }
}

int flb_log_event_decoder_unpack_timestamp(msgpack_object *input,
                                           struct flb_time *output)
{
    flb_time_zero(output);

    if (input->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        output->tm.tv_sec  = input->via.u64;
    }
    else if(input->type == MSGPACK_OBJECT_FLOAT) {
        output->tm.tv_sec  = input->via.f64;
        output->tm.tv_nsec = ((input->via.f64 - output->tm.tv_sec) * 1000000000);
    }
    else if(input->type == MSGPACK_OBJECT_EXT) {
        if (input->via.ext.type != 0 || input->via.ext.size != 8) {
            return FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE;
        }

        output->tm.tv_sec  = FLB_BSWAP_32(*((uint32_t *) &input->via.ext.ptr[0]));
        output->tm.tv_nsec = FLB_BSWAP_32(*((uint32_t *) &input->via.ext.ptr[4]));
    }
    else {
        return FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE;
    }

    return FLB_EVENT_DECODER_SUCCESS;
}

int flb_log_event_decoder_next(struct flb_log_event_decoder *context,
                               struct flb_log_event *event)
{
    msgpack_object *timestamp;
    msgpack_object *metadata;
    int             result;
    int             format;
    msgpack_object *header;
    msgpack_object *body;
    msgpack_object *root;

    if (context == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
    }

    if (event == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT;
    }

    memset(event, 0, sizeof(struct flb_log_event));

    result = msgpack_unpack_next(&context->unpacked_event,
                                 context->buffer,
                                 context->length,
                                 &context->offset);

    if (result != MSGPACK_UNPACK_SUCCESS) {
        return FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE;
    }

    /* Ensure that the root element is a 2 element array*/
    root = &context->unpacked_event.data;

    if (root->type != MSGPACK_OBJECT_ARRAY) {
        return FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE;
    }

    if (root->via.array.size != \
        FLB_LOG_EVENT_EXPECTED_ROOT_ELEMENT_COUNT) {
        return FLB_EVENT_DECODER_ERROR_WRONG_ROOT_SIZE;
    }

    header = &root->via.array.ptr[0];

    /* Determine if the first element is the header or
     * a legacy timestamp (int, float or ext).
     */
    if (header->type == MSGPACK_OBJECT_ARRAY) {
        if (header->via.array.size != \
            FLB_LOG_EVENT_EXPECTED_HEADER_ELEMENT_COUNT) {
            return FLB_EVENT_DECODER_ERROR_WRONG_HEADER_SIZE;
        }

        timestamp = &header->via.array.ptr[0];
        metadata = &header->via.array.ptr[1];

        format = FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2;
    }
    else {
        header = NULL;
        timestamp = &root->via.array.ptr[0];
        metadata = context->empty_map;

        format = FLB_LOG_EVENT_FORMAT_FORWARD;
    }

    if (timestamp->type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
        timestamp->type != MSGPACK_OBJECT_FLOAT &&
        timestamp->type != MSGPACK_OBJECT_EXT) {
        return FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE;
    }

    if (metadata->type != MSGPACK_OBJECT_MAP) {
        return FLB_EVENT_DECODER_ERROR_WRONG_METADATA_TYPE;
    }

    body = &root->via.array.ptr[1];

    if (body->type != MSGPACK_OBJECT_MAP) {
        return FLB_EVENT_DECODER_ERROR_WRONG_BODY_TYPE;
    }

    result = flb_log_event_decoder_unpack_timestamp(timestamp, &event->timestamp);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        return result;
    }

    event->raw_timestamp = timestamp;
    event->metadata = metadata;
    event->format = format;
    event->body = body;

    return FLB_EVENT_DECODER_SUCCESS;
}

struct flb_log_event_encoder *flb_log_event_encoder_create(int format)
{
    struct flb_log_event_encoder *context;

    if (format < FLB_LOG_EVENT_FORMAT_FORWARD ||
        format > FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
        return NULL;
    }

    context = (struct flb_log_event_encoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_encoder));

    if (context != NULL) {
        context->format = format;

        msgpack_sbuffer_init(&context->buffer);
        msgpack_packer_init(&context->packer,
                            &context->buffer,
                            msgpack_sbuffer_write);
    }

    return context;
}

void flb_log_event_encoder_reset(struct flb_log_event_encoder *context)
{
    msgpack_sbuffer_clear(&context->buffer);
}

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context)
{
    if (context != NULL) {
        msgpack_sbuffer_destroy(&context->buffer);

        flb_free(context);
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
    int result;

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

    return result;
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

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_produce_current_timestamp(
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

int flb_log_event_encoder_produce_empty_metadata(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    return flb_log_event_encoder_pack_empty_object(context, MSGPACK_OBJECT_MAP);
}

int flb_log_event_encoder_produce_empty_body(
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
        context->output_buffer = context->buffer.data;
        context->output_length = context->buffer.size;
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
        result = flb_log_event_encoder_produce_current_timestamp(context, NULL);
    }
    else {
        result = flb_log_event_encoder_produce_timestamp(context,
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

int flb_log_event_encoder_append_msgpack_object(struct flb_log_event_encoder *context,
                                                struct flb_time *timestamp,
                                                msgpack_object *metadata,
                                                msgpack_object *body)

{
    struct flb_log_event_encoder_msgpack_components components;

    components.timestamp = timestamp;
    components.metadata = metadata;
    components.body = body;

    return flb_log_event_encoder_append(context,
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
        result = flb_log_event_encoder_produce_current_timestamp(context, NULL);
    }
    else {
        result = flb_log_event_encoder_produce_timestamp(context,
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

int flb_log_event_encoder_append_msgpack_raw(struct flb_log_event_encoder *context,
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

    return flb_log_event_encoder_append(context,
                                        flb_log_event_encoder_produce_raw_msgpack_component_timestamp,
                                        flb_log_event_encoder_produce_raw_msgpack_component_metadata,
                                        flb_log_event_encoder_produce_raw_msgpack_component_body,
                                        (void *) &components);
}
