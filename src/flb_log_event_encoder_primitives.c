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

static inline \
int translate_msgpack_encoder_result(int value)
{
    if (value != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_append_value(
        struct flb_log_event_encoder *context,
        int target_field,
        int increment_entry_count,
        int value_type,
        char *value_buffer,
        size_t value_length)
{
    int                                         result;
    struct flb_log_event_encoder_dynamic_field *field;

    if (value_type < FLB_LOG_EVENT_STRING_MIN_VALUE_TYPE ||
        value_type > FLB_LOG_EVENT_STRING_MAX_VALUE_TYPE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_log_event_encoder_get_field(context, target_field, &field);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        if (increment_entry_count) {
            result = flb_log_event_encoder_dynamic_field_append(field);
        }

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            if (value_type == FLB_LOG_EVENT_STRING_LENGTH_VALUE_TYPE) {
                result = msgpack_pack_str(&field->packer, value_length);
            }
            else if (value_type == FLB_LOG_EVENT_BINARY_LENGTH_VALUE_TYPE) {
                result = msgpack_pack_bin(&field->packer, value_length);
            }
            else if (value_type == FLB_LOG_EVENT_EXT_LENGTH_VALUE_TYPE) {
                result = msgpack_pack_ext(&field->packer, value_length,
                                          *((int8_t *) value_buffer));
            }
            else if (value_type == FLB_LOG_EVENT_NULL_VALUE_TYPE) {
                result = msgpack_pack_nil(&field->packer);
            }
            else {
                if (value_buffer == NULL) {
                    return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
                }

                if (value_type == FLB_LOG_EVENT_STRING_BODY_VALUE_TYPE) {
                    result = msgpack_pack_str_body(&field->packer,
                                                   value_buffer,
                                                   value_length);
                }
                else if (value_type == FLB_LOG_EVENT_BINARY_BODY_VALUE_TYPE) {
                    result = msgpack_pack_bin_body(&field->packer,
                                                   value_buffer,
                                                   value_length);
                }
                else if (value_type == FLB_LOG_EVENT_EXT_BODY_VALUE_TYPE) {
                    result = msgpack_pack_ext_body(&field->packer,
                                                   value_buffer,
                                                   value_length);
                }
                else if (value_type == FLB_LOG_EVENT_CHAR_VALUE_TYPE) {
                    result = msgpack_pack_char(&field->packer,
                                               *((char *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_INT8_VALUE_TYPE) {
                    result = msgpack_pack_int8(&field->packer,
                                               *((int8_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_INT16_VALUE_TYPE) {
                    result = msgpack_pack_int16(&field->packer,
                                                *((int16_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_INT32_VALUE_TYPE) {
                    result = msgpack_pack_int32(&field->packer,
                                                *((int32_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_INT64_VALUE_TYPE) {
                    result = msgpack_pack_int64(&field->packer,
                                                *((int64_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_UINT8_VALUE_TYPE) {
                    result = msgpack_pack_uint8(&field->packer,
                                                *((uint8_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_UINT16_VALUE_TYPE) {
                    result = msgpack_pack_uint16(&field->packer,
                                                 *((uint16_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_UINT32_VALUE_TYPE) {
                    result = msgpack_pack_uint32(&field->packer,
                                                 *((uint32_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_UINT64_VALUE_TYPE) {
                    result = msgpack_pack_uint64(&field->packer,
                                                 *((uint64_t *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_DOUBLE_VALUE_TYPE) {
                    result = msgpack_pack_double(&field->packer,
                                                 *((double *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_BOOLEAN_VALUE_TYPE) {
                    if (*((int *) value_buffer)) {
                        result = msgpack_pack_true(&field->packer);
                    }
                    else {
                        result = msgpack_pack_false(&field->packer);
                    }
                }
                else if (value_type == FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE_TYPE) {
                    result = msgpack_pack_object(
                                &field->packer,
                                *((msgpack_object *) value_buffer));
                }
                else if (value_type == FLB_LOG_EVENT_MSGPACK_RAW_VALUE_TYPE) {
                    result = msgpack_pack_str_body(&field->packer,
                                                   value_buffer,
                                                   value_length);
                }
                else {
                    return  FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
                }

                result = translate_msgpack_encoder_result(result);
            }
        }
    }

    return result;
}

int flb_log_event_encoder_append_binary_length(
        struct flb_log_event_encoder *context,
        int target_field,
        size_t length)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_BINARY_LENGTH_VALUE_TYPE,
            NULL, length);
}

int flb_log_event_encoder_append_binary_body(
        struct flb_log_event_encoder *context,
        int target_field,
        char *value,
        size_t length)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_FALSE,
            FLB_LOG_EVENT_BINARY_BODY_VALUE_TYPE,
            value, length);
}

int flb_log_event_encoder_append_ext_length(
        struct flb_log_event_encoder *context,
        int target_field,
        int8_t type,
        size_t length)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_EXT_LENGTH_VALUE_TYPE,
            (char *) &type, length);
}

int flb_log_event_encoder_append_ext_body(
        struct flb_log_event_encoder *context,
        int target_field,
        char *value,
        size_t length)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_FALSE,
            FLB_LOG_EVENT_EXT_BODY_VALUE_TYPE,
            value, length);
}

int flb_log_event_encoder_append_string_length(
        struct flb_log_event_encoder *context,
        int target_field,
        size_t length)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_STRING_LENGTH_VALUE_TYPE,
            NULL, length);
}

int flb_log_event_encoder_append_string_body(
        struct flb_log_event_encoder *context,
        int target_field,
        char *value,
        size_t length)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_FALSE,
            FLB_LOG_EVENT_STRING_BODY_VALUE_TYPE,
            value, length);
}
int flb_log_event_encoder_append_int8(
        struct flb_log_event_encoder *context,
        int target_field,
        int8_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_INT8_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_int16(
        struct flb_log_event_encoder *context,
        int target_field,
        int16_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_INT16_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_int32(
        struct flb_log_event_encoder *context,
        int target_field,
        int32_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_INT32_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_int64(
        struct flb_log_event_encoder *context,
        int target_field,
        int64_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_INT64_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_uint8(
        struct flb_log_event_encoder *context,
        int target_field,
        uint8_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_UINT8_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_uint16(
        struct flb_log_event_encoder *context,
        int target_field,
        uint16_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_UINT16_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_uint32(
        struct flb_log_event_encoder *context,
        int target_field,
        uint32_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_UINT32_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_uint64(
        struct flb_log_event_encoder *context,
        int target_field,
        uint64_t value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_UINT64_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_double(
    struct flb_log_event_encoder *context,
    int target_field,
    double value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_DOUBLE_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_boolean(
    struct flb_log_event_encoder *context,
    int target_field,
    int value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_BOOLEAN_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_null(
        struct flb_log_event_encoder *context,
        int target_field)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_NULL_VALUE_TYPE,
            NULL, 0);
}

int flb_log_event_encoder_append_character(
        struct flb_log_event_encoder *context,
        int target_field,
        char value)
{
    return flb_log_event_encoder_append_value(
            context, target_field, FLB_TRUE,
            FLB_LOG_EVENT_CHAR_VALUE_TYPE,
            (char *) &value, 0);
}

int flb_log_event_encoder_append_binary(
        struct flb_log_event_encoder *context,
        int target_field,
        char *value,
        size_t length)
{
    int result;

    result = flb_log_event_encoder_append_binary_length(
                context,
                target_field,
                length);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_binary_body(
                    context,
                    target_field,
                    value,
                    length);
    }

    return result;
}

int flb_log_event_encoder_append_string(
        struct flb_log_event_encoder *context,
        int target_field,
        char *value,
        size_t length)
{
    int result;

    result = flb_log_event_encoder_append_string_length(
                context,
                target_field,
                length);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_string_body(
                    context,
                    target_field,
                    value,
                    length);
    }

    return result;
}

int flb_log_event_encoder_append_ext(
        struct flb_log_event_encoder *context,
        int target_field,
        int8_t type,
        char *value,
        size_t length)
{
    int result;

    result = flb_log_event_encoder_append_ext_length(
                context,
                target_field,
                type,
                length);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_append_ext_body(
                    context,
                    target_field,
                    value,
                    length);
    }

    return result;
}

int flb_log_event_encoder_append_cstring(
        struct flb_log_event_encoder *context,
        int target_field,
        char *value)
{
    return flb_log_event_encoder_append_string(
            context,
            target_field,
            value,
            strlen(value));
}

int flb_log_event_encoder_append_msgpack_object(
    struct flb_log_event_encoder *context,
    int target_field,
    msgpack_object *value)
{
    const int value_type = FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE_TYPE;

    return flb_log_event_encoder_append_value(context, target_field,
                                              FLB_TRUE, value_type,
                                              (char *) value, 0);
}

int flb_log_event_encoder_append_raw_msgpack(
    struct flb_log_event_encoder *context,
    int target_field,
    char *value_buffer,
    size_t value_size)
{
    const int value_type = FLB_LOG_EVENT_MSGPACK_RAW_VALUE_TYPE;

    return flb_log_event_encoder_append_value(context, target_field,
                                              FLB_TRUE, value_type,
                                              value_buffer, value_size);
}


int flb_log_event_encoder_append_timestamp(
    struct flb_log_event_encoder *context,
    int target_field,
    struct flb_time *value)
{
    if (context->format == FLB_LOG_EVENT_FORMAT_FORWARD_LEGACY) {
        return flb_log_event_encoder_append_legacy_timestamp(
                    context, target_field, value);
    }
    else if (context->format == FLB_LOG_EVENT_FORMAT_FORWARD) {
        return flb_log_event_encoder_append_forward_v1_timestamp(
                    context, target_field, value);
    }
    else if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V1) {
        return flb_log_event_encoder_append_fluent_bit_v1_timestamp(
                    context, target_field, value);
    }
    else if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
        return flb_log_event_encoder_append_fluent_bit_v2_timestamp(
                    context, target_field, value);
    }
    else {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }
}

int flb_log_event_encoder_append_legacy_timestamp(
    struct flb_log_event_encoder *context,
    int target_field,
    struct flb_time *value)
{
    const int value_type = FLB_LOG_EVENT_UINT64_VALUE_TYPE;
    uint64_t  timestamp;

    timestamp = value->tm.tv_sec;

    return flb_log_event_encoder_append_value(context, target_field,
                                              FLB_TRUE, value_type,
                                              (char *) &timestamp, 0);
}

int flb_log_event_encoder_append_forward_v1_timestamp(
    struct flb_log_event_encoder *context,
    int target_field,
    struct flb_time *timestamp)
{
    uint32_t value[2];

    value[0] = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) timestamp->tm.tv_sec);
    value[1] = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) timestamp->tm.tv_nsec);

    return flb_log_event_encoder_append_ext(context, target_field,
                                            0, (char *) value, 8);
}

int flb_log_event_encoder_append_fluent_bit_v1_timestamp(
    struct flb_log_event_encoder *context,
    int target_field,
    struct flb_time *value)
{
    return flb_log_event_encoder_append_forward_v1_timestamp(context,
                                                             target_field,
                                                             value);
}

int flb_log_event_encoder_append_fluent_bit_v2_timestamp(
    struct flb_log_event_encoder *context,
    int target_field,
    struct flb_time *value)
{
    return flb_log_event_encoder_append_fluent_bit_v1_timestamp(context,
                                                                target_field,
                                                                value);
}

int flb_log_event_encoder_append_values_unsafe(
        struct flb_log_event_encoder *context,
        int target_field,
        va_list arguments)
{
    int8_t  current_ext_type;
    size_t  processed_values;
    char   *buffer_address;
    int     value_type;
    int     result;

    processed_values = 0;
    result = FLB_EVENT_ENCODER_SUCCESS;

    for (processed_values = 0 ;
         processed_values < FLB_EVENT_ENCODER_VALUE_LIMIT &&
         result == FLB_EVENT_ENCODER_SUCCESS ;
         processed_values++) {
        value_type = va_arg(arguments, int);

        if (value_type == FLB_LOG_EVENT_APPEND_TERMINATOR_VALUE_TYPE) {
            break;
        }
        else if (value_type == FLB_LOG_EVENT_STRING_LENGTH_VALUE_TYPE) {
            result = flb_log_event_encoder_append_string_length(context,
                        target_field,
                        va_arg(arguments, size_t));
        }
        else if (value_type == FLB_LOG_EVENT_STRING_BODY_VALUE_TYPE) {
            buffer_address = va_arg(arguments, char *);

            result = flb_log_event_encoder_append_string_body(context,
                        target_field,
                        buffer_address,
                        va_arg(arguments, size_t));
        }
        else if (value_type == FLB_LOG_EVENT_BINARY_LENGTH_VALUE_TYPE) {
            result = flb_log_event_encoder_append_binary_length(context,
                        target_field,
                        va_arg(arguments, size_t));
        }
        else if (value_type == FLB_LOG_EVENT_BINARY_BODY_VALUE_TYPE) {
            buffer_address = va_arg(arguments, char *);

            result = flb_log_event_encoder_append_binary_body(context,
                        target_field,
                        buffer_address,
                        va_arg(arguments, size_t));
        }
        else if (value_type == FLB_LOG_EVENT_EXT_LENGTH_VALUE_TYPE) {
            current_ext_type = (int8_t) va_arg(arguments, int);

            result = flb_log_event_encoder_append_ext_length(context,
                        target_field,
                        current_ext_type,
                        va_arg(arguments, size_t));
        }
        else if (value_type == FLB_LOG_EVENT_EXT_BODY_VALUE_TYPE) {
            buffer_address = va_arg(arguments, char *);

            result = flb_log_event_encoder_append_ext_body(context,
                        target_field,
                        buffer_address,
                        va_arg(arguments, size_t));
        }
        else if (value_type == FLB_LOG_EVENT_NULL_VALUE_TYPE) {
            result = flb_log_event_encoder_append_null(context,
                        target_field);
        }
        else if (value_type == FLB_LOG_EVENT_CHAR_VALUE_TYPE) {
            result = flb_log_event_encoder_append_character(context,
                        target_field,
                        (char) va_arg(arguments, int));
        }
        else if (value_type == FLB_LOG_EVENT_INT8_VALUE_TYPE) {
            result = flb_log_event_encoder_append_int8(context,
                        target_field,
                        (int8_t) va_arg(arguments, int));
        }
        else if (value_type == FLB_LOG_EVENT_INT16_VALUE_TYPE) {
            result = flb_log_event_encoder_append_int16(context,
                        target_field,
                        (int16_t) va_arg(arguments, int));
        }
        else if (value_type == FLB_LOG_EVENT_INT32_VALUE_TYPE) {
            result = flb_log_event_encoder_append_int32(context,
                        target_field,
                        va_arg(arguments, int32_t));
        }
        else if (value_type == FLB_LOG_EVENT_INT64_VALUE_TYPE) {
            result = flb_log_event_encoder_append_int64(context,
                        target_field,
                        va_arg(arguments, int64_t));
        }
        else if (value_type == FLB_LOG_EVENT_UINT8_VALUE_TYPE) {
            result = flb_log_event_encoder_append_uint8(context,
                        target_field,
                        (uint8_t) va_arg(arguments, unsigned int));
        }
        else if (value_type == FLB_LOG_EVENT_UINT16_VALUE_TYPE) {
            result = flb_log_event_encoder_append_uint16(context,
                        target_field,
                        (uint16_t) va_arg(arguments, unsigned int));
        }
        else if (value_type == FLB_LOG_EVENT_UINT32_VALUE_TYPE) {
            result = flb_log_event_encoder_append_uint32(context,
                        target_field,
                        va_arg(arguments, uint32_t));
        }
        else if (value_type == FLB_LOG_EVENT_UINT64_VALUE_TYPE) {
            result = flb_log_event_encoder_append_uint64(context,
                        target_field,
                        va_arg(arguments, uint64_t));
        }
        else if (value_type == FLB_LOG_EVENT_DOUBLE_VALUE_TYPE) {
            result = flb_log_event_encoder_append_double(context,
                        target_field,
                        va_arg(arguments, double));
        }
        else if (value_type == FLB_LOG_EVENT_BOOLEAN_VALUE_TYPE) {
            result = flb_log_event_encoder_append_boolean(context,
                        target_field,
                        va_arg(arguments, int));
        }
        else if (value_type == FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE_TYPE) {
            result = flb_log_event_encoder_append_msgpack_object(context,
                        target_field,
                        va_arg(arguments, msgpack_object *));
        }
        else if (value_type == FLB_LOG_EVENT_MSGPACK_RAW_VALUE_TYPE) {
            buffer_address = va_arg(arguments, char *);

            result = flb_log_event_encoder_append_raw_msgpack(context,
                        target_field,
                        buffer_address,
                        va_arg(arguments, size_t));
        }
        else if (value_type == FLB_LOG_EVENT_TIMESTAMP_VALUE_TYPE) {
            result = flb_log_event_encoder_append_timestamp(context,
                        target_field,
                        va_arg(arguments, struct flb_time *));
        }
        else if (value_type == FLB_LOG_EVENT_LEGACY_TIMESTAMP_VALUE_TYPE) {
            result = flb_log_event_encoder_append_legacy_timestamp(context,
                        target_field,
                        va_arg(arguments, struct flb_time *));
        }
        else if (value_type == FLB_LOG_EVENT_FORWARD_V1_TIMESTAMP_VALUE_TYPE) {
            result = flb_log_event_encoder_append_forward_v1_timestamp(context,
                        target_field,
                        va_arg(arguments, struct flb_time *));
        }
        else if (value_type == FLB_LOG_EVENT_FLUENT_BIT_V1_TIMESTAMP_VALUE_TYPE) {
            result = flb_log_event_encoder_append_fluent_bit_v1_timestamp(context,
                        target_field,
                        va_arg(arguments, struct flb_time *));
        }
        else if (value_type == FLB_LOG_EVENT_FLUENT_BIT_V2_TIMESTAMP_VALUE_TYPE) {
            result = flb_log_event_encoder_append_fluent_bit_v2_timestamp(context,
                        target_field,
                        va_arg(arguments, struct flb_time *));
        }
        else {
            result = FLB_EVENT_ENCODER_ERROR_INVALID_VALUE_TYPE;
        }
    }

    if (processed_values >= FLB_EVENT_ENCODER_VALUE_LIMIT) {
        flb_error("Log event encoder : value count limit exceeded");
    }

    return result;
}
