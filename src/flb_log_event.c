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

static int flb_event_decoder_verify_root(
    struct flb_log_event_decoder *context)
{
    msgpack_object *current_object;

    if (context == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
    }

    current_object = &context->unpacked.data;

    if (current_object->type != MSGPACK_OBJECT_ARRAY) {
        return FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE;
    }

    if (current_object->via.array.size != \
        FLB_LOG_EVENT_EXPECTED_ROOT_ELEMENT_COUNT) {
        return FLB_EVENT_DECODER_ERROR_WRONG_ROOT_SIZE;
    }

    return FLB_EVENT_DECODER_SUCCESS;
}

static int flb_event_decoder_verify_header(
    struct flb_log_event_decoder *context)
{
    msgpack_object *current_object;

    if (context == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
    }

    current_object = &context->unpacked.data;
    current_object = &current_object->via.array.ptr[0];

    if (current_object->type != MSGPACK_OBJECT_ARRAY) {
        return FLB_EVENT_DECODER_ERROR_WRONG_HEADER_TYPE;
    }

    if (current_object->via.array.size != \
        FLB_LOG_EVENT_EXPECTED_HEADER_ELEMENT_COUNT) {
        return FLB_EVENT_DECODER_ERROR_WRONG_HEADER_SIZE;
    }

    return FLB_EVENT_DECODER_SUCCESS;
}

static int flb_event_decoder_verify_body(
    struct flb_log_event_decoder *context)
{
    msgpack_object *current_object;

    if (context == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
    }

    current_object = &context->unpacked.data;
    current_object = &current_object->via.array.ptr[1];

    if (current_object->type != MSGPACK_OBJECT_MAP) {
        return FLB_EVENT_DECODER_ERROR_WRONG_BODY_TYPE;
    }

    return FLB_EVENT_DECODER_SUCCESS;
}

int flb_event_decoder_verify_entry(struct flb_log_event_decoder *context)
{
    int result;

    result = flb_event_decoder_verify_root(context);

    if (result == FLB_EVENT_DECODER_SUCCESS) {
        result = flb_event_decoder_verify_header(context);
    }

    if (result == FLB_EVENT_DECODER_SUCCESS) {
        result = flb_event_decoder_verify_body(context);
    }

    return result;
}

int flb_event_decoder_fetch_header(struct flb_log_event_decoder *context,
                                   msgpack_object **header)
{
    msgpack_object *current_object;
    int             result;

    if (header == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_event_decoder_verify_entry(context);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        return result;
    }

    current_object = &context->unpacked.data;
    current_object = &current_object->via.array.ptr[0];

    *header = current_object;

    return FLB_EVENT_DECODER_SUCCESS;
}

int flb_event_decoder_fetch_timestamp(struct flb_log_event_decoder *context,
                                      msgpack_object **timestamp)
{
    msgpack_object *current_object;
    int             result;

    if (timestamp == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_event_decoder_fetch_header(context, &current_object);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        return result;
    }

    current_object = &current_object->via.array.ptr[0];

    *timestamp = current_object;

    return FLB_EVENT_DECODER_SUCCESS;
}

int flb_event_decoder_fetch_metadata(struct flb_log_event_decoder *context,
                                     msgpack_object **metadata)
{
    msgpack_object *current_object;
    int             result;

    if (metadata == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_event_decoder_fetch_header(context, &current_object);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        return result;
    }

    current_object = &current_object->via.array.ptr[1];

    *metadata = current_object;

    return FLB_EVENT_DECODER_SUCCESS;
}

int flb_event_decoder_fetch_body(struct flb_log_event_decoder *context,
                                 msgpack_object **body)
{
    msgpack_object *current_object;
    int             result;

    if (body == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_event_decoder_verify_entry(context);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        return result;
    }

    current_object = &context->unpacked.data;
    current_object = &current_object->via.array.ptr[1];

    *body = current_object;

    return FLB_EVENT_DECODER_SUCCESS;
}

struct flb_log_event_decoder *flb_log_event_decoder_create(
    const char *input_buffer,
    size_t input_length)
{
    struct flb_log_event_decoder *context;

    context = (struct flb_log_event_decoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_decoder));

    if (context != NULL) {
        memset(context, 0, sizeof(struct flb_log_event_decoder));

        context->buffer = input_buffer;
        context->length = input_length;

        msgpack_unpacked_init(&context->unpacked);
    }

    return context;
}

void flb_log_event_decoder_destroy(struct flb_log_event_decoder *context)
{
    if (context != NULL) {
        msgpack_unpacked_destroy(&context->unpacked);

        free(context);
    }
}

int flb_log_event_decoder_next(struct flb_log_event_decoder *context,
                               struct flb_log_event *record)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
    }

    result = msgpack_unpack_next(&context->unpacked,
                                 context->buffer,
                                 context->length,
                                 &context->offset);

    if (result != MSGPACK_UNPACK_SUCCESS) {
        result = FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE;
    }
    else {
        result = FLB_EVENT_DECODER_SUCCESS;
    }

    if (result == FLB_EVENT_DECODER_SUCCESS) {
        result = flb_event_decoder_fetch_timestamp(context,
                                                   &record->raw_timestamp);
    }

    if (result == FLB_EVENT_DECODER_SUCCESS) {
        result = flb_event_decoder_fetch_metadata(context,
                                                  &record->metadata);
    }

    if (result == FLB_EVENT_DECODER_SUCCESS) {
        result = flb_event_decoder_fetch_body(context,
                                              &record->body);
    }

    if (result == FLB_EVENT_DECODER_SUCCESS) {
        result = flb_time_msgpack_to_time(&record->timestamp,
                                          record->raw_timestamp);
    }

    return result;
}

struct flb_log_event_encoder *flb_log_event_encoder_create()
{
    struct flb_log_event_encoder *context;

    context = (struct flb_log_event_encoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_encoder));

    if (context != NULL) {
        memset(context, 0, sizeof(struct flb_log_event_encoder));

        msgpack_sbuffer_init(&context->buffer);
        msgpack_packer_init(&context->packer,
                            &context->buffer,
                            msgpack_sbuffer_write);
    }

    return context;
}

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context)
{
    if (context != NULL) {
        msgpack_sbuffer_destroy(&context->buffer);

        flb_free(context);
    }
}

int flb_log_event_encoder_current_timestamp_callback(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    result = flb_time_append_to_msgpack(NULL,
                                        &context->packer,
                                        FLB_TIME_FMT_PRECISION_NS);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_empty_metadata_callback(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    result = msgpack_pack_map(&context->packer, 0);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_empty_body_callback(
    struct flb_log_event_encoder *context,
    void *user_data)
{
    int result;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    result = msgpack_pack_map(&context->packer, 0);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_append_ex(struct flb_log_event_encoder *context,
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
        timestamp_callback = flb_log_event_encoder_current_timestamp_callback;
    }

    if (metadata_callback == NULL) {
        metadata_callback = flb_log_event_encoder_empty_metadata_callback;
    }

    if (body_callback == NULL) {
        body_callback = flb_log_event_encoder_empty_body_callback;
    }

    /* outermost array */
    result = msgpack_pack_array(&context->packer, 2);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    /* header array */
    result = msgpack_pack_array(&context->packer, 2);

    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    result = timestamp_callback(context, user_data);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = metadata_callback(context, user_data);
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

int flb_log_event_encoder_append(struct flb_log_event_encoder *context,
                                 struct flb_time *timestamp,
                                 msgpack_object *metadata,
                                 msgpack_object *body)
{
    int result;

    if (context == NULL) {
        return -1;
    }

    /* outermost array */
    msgpack_pack_array(&context->packer, 2);

    /* header array */
    msgpack_pack_array(&context->packer, 2);

    result = flb_time_append_to_msgpack(timestamp,
                                        &context->packer,
                                        FLB_TIME_FMT_PRECISION_NS);

    if (result != 0) {
        return -2;
    }

    if (metadata != NULL) {
        result = msgpack_pack_object(&context->packer, *metadata);
    }
    else {
        msgpack_pack_map(&context->packer, 0);
    }

    if (result != 0) {
        return -3;
    }

    if (body == NULL) {
        return -4;
    }

    result = msgpack_pack_object(&context->packer, *body);

    if (result != 0) {
        return -5;
    }

    context->output_buffer = context->buffer.data;
    context->output_length = context->buffer.size;

    return 0;
}
