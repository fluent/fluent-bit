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

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_encoder_primitives.h>
#include <fluent-bit/flb_byteswap.h>
#include <stdarg.h>
#include <string.h>

/*
 * Encoder hot-path optimization notes (emit_record / commit_record / metadata):
 *
 * 1. emit_record: For FLUENT_BIT_V2 we use a direct-emit path that writes
 *    the record string [ [timestamp, metadata], body ] directly into the
 *    main buffer (no root buffer build/copy), matching the original format.
 *
 * 2. Possible future improvements:
 *    - Batch metadata: add append_metadata_kv_batch() or allow multiple
 *      key-value pairs in one call to cut va_list and call overhead.
 *    - Inline / fast path: move begin_record/commit_record hot branches
 *      into a header so the compiler can inline for the common case.
 *    - Buffer growth: reserve space for the next record (e.g. typical
 *      metadata + body size) to reduce reallocs in msgpack_sbuffer.
 *    - dynamic_field_flush: when there is only one scope per field, avoid
 *      the scope loop (single commit then set data/size).
 */

void static inline flb_log_event_encoder_update_internal_state(
    struct flb_log_event_encoder *context)
{
    context->output_buffer = context->buffer.data;
    context->output_length = context->buffer.size;
}

void flb_log_event_encoder_reset(struct flb_log_event_encoder *context)
{
    flb_log_event_encoder_dynamic_field_reset(&context->metadata);
    flb_log_event_encoder_dynamic_field_reset(&context->body);
    flb_log_event_encoder_dynamic_field_reset(&context->root);

    msgpack_sbuffer_clear(&context->buffer);

    flb_log_event_encoder_update_internal_state(context);
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
    context->initialized = FLB_TRUE;
    context->format = format;

    msgpack_sbuffer_init(&context->buffer);
    msgpack_packer_init(&context->packer,
                        &context->buffer,
                        msgpack_sbuffer_write);

    flb_log_event_encoder_dynamic_field_init(&context->metadata,
                                             MSGPACK_OBJECT_MAP);

    flb_log_event_encoder_dynamic_field_init(&context->body,
                                             MSGPACK_OBJECT_MAP);

    flb_log_event_encoder_dynamic_field_init(&context->root,
                                             MSGPACK_OBJECT_ARRAY);

    return FLB_EVENT_ENCODER_SUCCESS;
}

struct flb_log_event_encoder *flb_log_event_encoder_create(int format)
{
    struct flb_log_event_encoder *context;
    int                           result;

    context = (struct flb_log_event_encoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_encoder));

    result = flb_log_event_encoder_init(context, format);

    if (context != NULL) {
        context->dynamically_allocated = FLB_TRUE;

        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_destroy(context);

            context = NULL;
        }
    }

    return context;
}

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context)
{
    if (context != NULL) {
        if (context->initialized) {
            flb_log_event_encoder_dynamic_field_destroy(&context->metadata);
            flb_log_event_encoder_dynamic_field_destroy(&context->body);
            flb_log_event_encoder_dynamic_field_destroy(&context->root);

            msgpack_sbuffer_destroy(&context->buffer);

            context->initialized = FLB_FALSE;
        }

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

int flb_log_event_encoder_emit_raw_record(struct flb_log_event_encoder *context,
                                          const char *buffer,
                                          size_t length)
{
    int result;

    result = msgpack_pack_str_body(&context->packer, buffer, length);

    if (result != 0) {
        result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }
    else {
        result = FLB_EVENT_ENCODER_SUCCESS;
    }

    flb_log_event_encoder_update_internal_state(context);
    flb_log_event_encoder_reset_record(context);

    return result;
}

/*
 * Optimized emit_record: for FLUENT_BIT_V2 appends the record as raw
 * msgpack array bytes [ [timestamp, metadata], body ] to the main buffer
 * (no root buffer build/copy), matching the slow path format.
 */
int flb_log_event_encoder_emit_record(struct flb_log_event_encoder *context)
{
    int      result;
    char     ts_buf[8];
    char     rec_header[5];
    uint32_t sec;
    uint32_t nsec;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    result = FLB_EVENT_ENCODER_SUCCESS;

    if (context->root.size == 0) {
        if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2 &&
            context->metadata.data != NULL && context->body.data != NULL) {
            /*
             * Direct-emit: append raw array bytes [ [timestamp, metadata], body ]
             * (fixarray 2, fixarray 2, fixext 8 type 0, 8b ts, metadata, body).
             * Do not wrap in a msgpack string; match slow path which uses
             * msgpack_pack_str_body(root.data, root.size) with no str header.
             */
            rec_header[0] = (char) 0x92;
            rec_header[1] = (char) 0x92;
            rec_header[2] = (char) 0xd7;
            rec_header[3] = (char) 0x00;

            result = msgpack_pack_str_body(&context->packer,
                                           rec_header, (size_t) 4);
            if (result == 0) {
                sec = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) context->timestamp.tm.tv_sec);
                nsec = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) context->timestamp.tm.tv_nsec);
                memcpy(&ts_buf[0], &sec, 4);
                memcpy(&ts_buf[4], &nsec, 4);
                result = msgpack_pack_str_body(&context->packer, ts_buf, 8);
            }
            if (result == 0) {
                result = msgpack_pack_str_body(&context->packer,
                                               context->metadata.data,
                                               context->metadata.size);
            }
            if (result == 0) {
                result = msgpack_pack_str_body(&context->packer,
                                               context->body.data,
                                               context->body.size);
            }
            if (result != 0) {
                result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
            }
            else {
                result = FLB_EVENT_ENCODER_SUCCESS;
            }
        }
        else {
            result = flb_log_event_encoder_root_begin_array(context);

            if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
                if (result == FLB_EVENT_ENCODER_SUCCESS) {
                    result = flb_log_event_encoder_root_begin_array(context);
                }
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_append_root_timestamp(
                            context, &context->timestamp);
            }

            if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
                if (result == FLB_EVENT_ENCODER_SUCCESS) {
                    result = flb_log_event_encoder_append_root_raw_msgpack(
                                context,
                                context->metadata.data,
                                context->metadata.size);
                }

                if (result == FLB_EVENT_ENCODER_SUCCESS) {
                    result = flb_log_event_encoder_root_commit_array(context);
                }
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_append_root_raw_msgpack(
                            context,
                            context->body.data,
                            context->body.size);
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_dynamic_field_flush(&context->root);
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS &&
                context->root.data != NULL && context->root.size > 0) {
                result = msgpack_pack_str_body(&context->packer,
                                               context->root.data,
                                               context->root.size);

                if (result != 0) {
                    result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                }
                else {
                    result = FLB_EVENT_ENCODER_SUCCESS;
                }
            }
        }
    }
    else if (result == FLB_EVENT_ENCODER_SUCCESS &&
             context->root.data != NULL && context->root.size > 0) {
        result = msgpack_pack_str_body(&context->packer,
                                       context->root.data,
                                       context->root.size);

        if (result != 0) {
            result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
        }
        else {
            result = FLB_EVENT_ENCODER_SUCCESS;
        }
    }

    flb_log_event_encoder_update_internal_state(context);
    flb_log_event_encoder_reset_record(context);

    return result;
}

int flb_log_event_encoder_reset_record(struct flb_log_event_encoder *context)
{
    flb_log_event_encoder_dynamic_field_reset(&context->metadata);
    flb_log_event_encoder_dynamic_field_reset(&context->body);
    flb_log_event_encoder_dynamic_field_reset(&context->root);

    flb_time_zero(&context->timestamp);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_rollback_record(struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_reset_record(context);
}

int flb_log_event_encoder_begin_record(struct flb_log_event_encoder *context)
{
    flb_log_event_encoder_reset_record(context);

    flb_log_event_encoder_metadata_begin_map(context);
    flb_log_event_encoder_body_begin_map(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_commit_record(struct flb_log_event_encoder *context)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_flush(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_flush(&context->body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_emit_record(context);
    }
    else {
        flb_log_event_encoder_reset_record(context);
    }

    return result;
}

int flb_log_event_encoder_set_timestamp(struct flb_log_event_encoder *context,
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

int flb_log_event_encoder_set_current_timestamp(struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_set_timestamp(context, NULL);
}

int flb_log_event_encoder_append_metadata_values_unsafe(struct flb_log_event_encoder *context, ...)
{
    va_list arguments;
    int     result;

    va_start(arguments, context);

    result = flb_log_event_encoder_append_values_unsafe(
            context,
            FLB_LOG_EVENT_METADATA,
            arguments);

    va_end(arguments);

    return result;
}

int flb_log_event_encoder_append_body_values_unsafe(
        struct flb_log_event_encoder *context,
        ...)
{
    va_list arguments;
    int     result;

    va_start(arguments, context);

    result = flb_log_event_encoder_append_values_unsafe(
            context,
            FLB_LOG_EVENT_BODY,
            arguments);

    va_end(arguments);

    return result;
}

int flb_log_event_encoder_append_root_values_unsafe(
        struct flb_log_event_encoder *context,
        ...)
{
    va_list arguments;
    int     result;

    va_start(arguments, context);

    result = flb_log_event_encoder_append_values_unsafe(
            context,
            FLB_LOG_EVENT_ROOT,
            arguments);

    va_end(arguments);

    return result;
}

const char *flb_log_event_encoder_get_error_description(int error_code)
{
    const char *ret;

    switch (error_code) {
    case FLB_EVENT_ENCODER_SUCCESS:
        ret = "Success";
        break;

    case FLB_EVENT_ENCODER_ERROR_UNSPECIFIED:
        ret = "Unspecified";
        break;

    case FLB_EVENT_ENCODER_ERROR_ALLOCATION_ERROR:
        ret = "Allocation error";
        break;

    case FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT:
        ret = "Invalid context";
        break;

    case FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT:
        ret = "Invalid argument";
        break;

    case FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE:
        ret = "Serialization failure";
        break;

    case FLB_EVENT_ENCODER_ERROR_INVALID_VALUE_TYPE:
        ret = "Invalid value type";
        break;

    default:
        ret = "Unknown error";
    }

    return ret;
}


int flb_log_event_encoder_group_init(struct flb_log_event_encoder *context)
{
    int ret;
    struct flb_time tm;

    ret = flb_log_event_encoder_begin_record(context);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_START, 0);
    ret = flb_log_event_encoder_set_timestamp(context, &tm);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

int flb_log_event_encoder_group_header_end(struct flb_log_event_encoder *context)
{
    int ret;

    ret = flb_log_event_encoder_commit_record(context);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

int flb_log_event_encoder_group_end(struct flb_log_event_encoder *context)
{
    int ret;
    struct flb_time tm;

    ret = flb_log_event_encoder_begin_record(context);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_END, 0);
    ret = flb_log_event_encoder_set_timestamp(context, &tm);
    if (ret == -1) {
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(context);
    if (ret == -1) {
        return -1;
    }

    return 0;
}
