/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_byteswap.h>
#include <fluent-bit/flb_compat.h>

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

        msgpack_unpacked_init(&context->unpacked_empty_map);

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

void flb_log_event_decoder_reset(struct flb_log_event_decoder *context,
                                 char *input_buffer,
                                 size_t input_length)
{
    context->offset = 0;
    context->buffer = input_buffer;
    context->length = input_length;
    context->last_result = FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA;
    context->current_group_metadata = NULL;
    context->current_group_attributes = NULL;

    msgpack_unpacked_destroy(&context->unpacked_group_record);
    msgpack_unpacked_init(&context->unpacked_group_record);

    msgpack_unpacked_destroy(&context->unpacked_event);
    msgpack_unpacked_init(&context->unpacked_event);
}

int flb_log_event_decoder_read_groups(struct flb_log_event_decoder *context,
                                      int read_groups)
{
    if (context == NULL) {
        return -1;
    }

    if (read_groups != FLB_TRUE && read_groups != FLB_FALSE) {
        return -1;
    }
    context->read_groups = read_groups;
    return 0;
}

int flb_log_event_decoder_init(struct flb_log_event_decoder *context,
                               char *input_buffer,
                               size_t input_length)
{
    if (context == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
    }

    memset(context, 0, sizeof(struct flb_log_event_decoder));

    context->dynamically_allocated = FLB_FALSE;
    context->initialized = FLB_TRUE;
    context->read_groups = FLB_FALSE;

    flb_log_event_decoder_reset(context, input_buffer, input_length);

    return create_empty_map(context);
}

struct flb_log_event_decoder *flb_log_event_decoder_create(
    char *input_buffer,
    size_t input_length)
{
    struct flb_log_event_decoder *context;
    int                           result;

    context = (struct flb_log_event_decoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_decoder));
    if (!context) {
        flb_errno();
        return NULL;
    }

    result = flb_log_event_decoder_init(context,
                                        input_buffer,
                                        input_length);

    if (context != NULL) {
        context->dynamically_allocated = FLB_TRUE;
        if (result != FLB_EVENT_DECODER_SUCCESS) {
            flb_log_event_decoder_destroy(context);
            context = NULL;
        }
    }

    return context;
}

void flb_log_event_decoder_destroy(struct flb_log_event_decoder *context)
{
    int dynamically_allocated;

    if (context != NULL) {
        if (context->initialized) {
            msgpack_unpacked_destroy(&context->unpacked_group_record);
            msgpack_unpacked_destroy(&context->unpacked_empty_map);
            msgpack_unpacked_destroy(&context->unpacked_event);
        }

        dynamically_allocated = context->dynamically_allocated;

        memset(context, 0, sizeof(struct flb_log_event_decoder));

        /* This might look silly and with most of the codebase including
         * this module as context it might be but just in case we choose
         * to stray away from the assumption of FLB_FALSE being zero and
         * FLB_TRUE being one in favor of explicitly comparing variables to
         * the the constants I will leave this here.
         */
        context->initialized = FLB_FALSE;

        if (dynamically_allocated) {
            flb_free(context);
        }
    }
}

int flb_log_event_decoder_decode_timestamp(msgpack_object *input,
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

        output->tm.tv_sec  =
            (int32_t) FLB_UINT32_TO_HOST_BYTE_ORDER(
                        FLB_ALIGNED_DWORD_READ(
                            (unsigned char *) &input->via.ext.ptr[0]));

        output->tm.tv_nsec  =
            (int32_t) FLB_UINT32_TO_HOST_BYTE_ORDER(
                        FLB_ALIGNED_DWORD_READ(
                            (unsigned char *) &input->via.ext.ptr[4]));
    }
    else {
        return FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE;
    }

    return FLB_EVENT_DECODER_SUCCESS;
}

int flb_event_decoder_decode_object(struct flb_log_event_decoder *context,
                                    struct flb_log_event *event,
                                    msgpack_object *input)
{
    msgpack_object *timestamp;
    msgpack_object *metadata;
    int             result;
    int             format;
    msgpack_object *header;
    msgpack_object *body;
    msgpack_object *root;

    memset(event, 0, sizeof(struct flb_log_event));

    /* Ensure that the root element is a 2 element array*/
    root = input;

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

    result = flb_log_event_decoder_decode_timestamp(timestamp, &event->timestamp);

    if (result != FLB_EVENT_DECODER_SUCCESS) {
        return result;
    }

    event->raw_timestamp = timestamp;
    event->metadata = metadata;
    event->format = format;
    event->body = body;
    event->root = root;

    context->record_base   = \
        (const char *) &context->buffer[context->previous_offset];
    context->record_length = context->offset - context->previous_offset;

    return FLB_EVENT_DECODER_SUCCESS;
}

int flb_log_event_decoder_get_last_result(struct flb_log_event_decoder *context)
{
    if (context->last_result == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA &&
        context->offset == context->length) {
        context->last_result = FLB_EVENT_DECODER_SUCCESS;
    }

    return context->last_result;
}

int flb_log_event_decoder_next(struct flb_log_event_decoder *context,
                               struct flb_log_event *event)
{
    int ret;
    int result;
    int record_type;
    size_t previous_offset;

    if (context == NULL) {
        return FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
    }
    if (context->length == 0) {
        context->last_result = FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA;
        return context->last_result;
    }

    context->record_base = NULL;
    context->record_length = 0;

    if (event == NULL) {
        context->last_result = FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT;
        return context->last_result;
    }

    previous_offset = context->offset;
    result = msgpack_unpack_next(&context->unpacked_event,
                                 context->buffer,
                                 context->length,
                                 &context->offset);

    if (result == MSGPACK_UNPACK_CONTINUE) {
        context->last_result = FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA;
        return context->last_result;
    }
    else if (result != MSGPACK_UNPACK_SUCCESS) {
        context->last_result = FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE;
        return context->last_result;
    }

    context->previous_offset = previous_offset;
    context->last_result = flb_event_decoder_decode_object(context,
                                                           event,
                                                           &context->unpacked_event.data);

    if (context->last_result == FLB_EVENT_DECODER_SUCCESS) {
        /* get log event type */
        ret = flb_log_event_decoder_get_record_type(event, &record_type);
        if (ret != 0) {
            context->current_group_metadata = NULL;
            context->current_group_attributes = NULL;

            context->last_result = FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE;
            return context->last_result;
        }

        /* Meta records such as the group opener and closer are identified by negative
         * timestamp values. In these cases we track the current group metadata and
         * attributes in order to transparently provide them through the log_event
         * structure but we also want to allow the client code raw access to such
         * records which is why the read_groups decoder context property is used
         * to determine the behavior.
         */
        if (record_type != FLB_LOG_EVENT_NORMAL) {
            msgpack_unpacked_destroy(&context->unpacked_group_record);

            if (record_type == FLB_LOG_EVENT_GROUP_START) {
                /*
                 * Transfer zone ownership from unpacked_event to unpacked_group_record
                 * instead of using memcpy. This prevents double-free issues when
                 * both structures would otherwise reference the same zone.
                 */
                context->unpacked_group_record.zone = msgpack_unpacked_release_zone(&context->unpacked_event);
                context->unpacked_group_record.data = context->unpacked_event.data;

                /*
                 * Extract pointers from the transferred data structure to ensure they
                 * remain valid. The pointers must come from unpacked_group_record.data
                 * since that's where the zone (and the data) now reside.
                 */
                if (context->unpacked_group_record.data.type == MSGPACK_OBJECT_ARRAY &&
                    context->unpacked_group_record.data.via.array.size == 2) {
                    msgpack_object *header = &context->unpacked_group_record.data.via.array.ptr[0];
                    msgpack_object *root_body = &context->unpacked_group_record.data.via.array.ptr[1];

                    if (header->type == MSGPACK_OBJECT_ARRAY &&
                        header->via.array.size == 2) {
                        context->current_group_metadata = &header->via.array.ptr[1];
                    }
                    else {
                        context->current_group_metadata = context->empty_map;
                    }
                    context->current_group_attributes = root_body;
                }
                else {
                    /* Fallback to using event pointers if structure is unexpected */
                    context->current_group_metadata = event->metadata;
                    context->current_group_attributes = event->body;
                }
            }
            else {
                context->current_group_metadata = NULL;
                context->current_group_attributes = NULL;
            }

            if (context->read_groups != FLB_TRUE) {
                /*
                 * Skip group markers by recursively calling to get next record.
                 * msgpack_unpack_next will properly destroy and reinitialize
                 * unpacked_event, so no explicit cleanup needed here.
                 */
                memset(event, 0, sizeof(struct flb_log_event));
                return flb_log_event_decoder_next(context, event);
            }
        }
        else {
            event->group_metadata = context->current_group_metadata;
            event->group_attributes = context->current_group_attributes;
        }
    }

    return context->last_result;
}

int flb_log_event_decoder_get_record_type(struct flb_log_event *event, int32_t *type)
{
    int32_t s;

    s = (int32_t) event->timestamp.tm.tv_sec;

    if (s >= 0) {
        *type = FLB_LOG_EVENT_NORMAL;
        return 0;
    }
    else if (s == FLB_LOG_EVENT_GROUP_START) {
        *type = FLB_LOG_EVENT_GROUP_START;
        return 0;
    }
    else if (s == FLB_LOG_EVENT_GROUP_END) {
        *type = FLB_LOG_EVENT_GROUP_END;
        return 0;
    }

    return -1;
}

const char *flb_log_event_decoder_get_error_description(int error_code)
{
    const char *ret;

    switch (error_code) {
    case FLB_EVENT_DECODER_SUCCESS:
        ret = "Success";
        break;

    case FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE:
        ret = "Initialization failure";
        break;

    case FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT:
        ret = "Invalid context";
        break;

    case FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT:
        ret = "Invalid argument";
        break;

    case FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE:
        ret = "Wrong root type";
        break;

    case FLB_EVENT_DECODER_ERROR_WRONG_ROOT_SIZE:
        ret = "Wrong root size";
        break;

    case FLB_EVENT_DECODER_ERROR_WRONG_HEADER_TYPE:
        ret = "Wrong header type";
        break;

    case FLB_EVENT_DECODER_ERROR_WRONG_HEADER_SIZE:
        ret = "Wrong header size";
        break;

    case FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE:
        ret = "Wrong timestamp type";
        break;

    case FLB_EVENT_DECODER_ERROR_WRONG_METADATA_TYPE:
        ret = "Wrong metadata type";
        break;

    case FLB_EVENT_DECODER_ERROR_WRONG_BODY_TYPE:
        ret = "Wrong body type";
        break;

    case FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE:
        ret = "Deserialization failure";
        break;

    case FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA:
        ret = "Insufficient data";
        break;

    default:
        ret = "Unknown error";
    }
    return ret;
}
