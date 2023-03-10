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

#ifndef FLB_LOG_EVENT_ENCODER_H
#define FLB_LOG_EVENT_ENCODER_H

#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_log_event_encoder_dynamic_field.h>

#include <msgpack.h>

#define FLB_EVENT_ENCODER_SUCCESS                        0
#define FLB_EVENT_ENCODER_ERROR_ALLOCATION_ERROR        -1
#define FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT         -2
#define FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT        -3
#define FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE   -4
#define FLB_EVENT_ENCODER_ERROR_INVALID_VALUE_TYPE      -5

#define FLB_LOG_EVENT_APPEND_TERMINATOR_VALUE_TYPE       0

#define FLB_LOG_EVENT_STRING_LENGTH_VALUE_TYPE           1
#define FLB_LOG_EVENT_STRING_BODY_VALUE_TYPE             2
#define FLB_LOG_EVENT_BINARY_LENGTH_VALUE_TYPE           3
#define FLB_LOG_EVENT_BINARY_BODY_VALUE_TYPE             4
#define FLB_LOG_EVENT_EXT_LENGTH_VALUE_TYPE              5
#define FLB_LOG_EVENT_EXT_BODY_VALUE_TYPE                6
#define FLB_LOG_EVENT_CHAR_VALUE_TYPE                    7
#define FLB_LOG_EVENT_INT8_VALUE_TYPE                    8
#define FLB_LOG_EVENT_INT16_VALUE_TYPE                   9
#define FLB_LOG_EVENT_INT32_VALUE_TYPE                   10
#define FLB_LOG_EVENT_INT64_VALUE_TYPE                   11
#define FLB_LOG_EVENT_UINT8_VALUE_TYPE                   12
#define FLB_LOG_EVENT_UINT16_VALUE_TYPE                  13
#define FLB_LOG_EVENT_UINT32_VALUE_TYPE                  14
#define FLB_LOG_EVENT_UINT64_VALUE_TYPE                  15
#define FLB_LOG_EVENT_DOUBLE_VALUE_TYPE                  16
#define FLB_LOG_EVENT_BOOLEAN_VALUE_TYPE                 17
#define FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE_TYPE          18
#define FLB_LOG_EVENT_MSGPACK_RAW_VALUE_TYPE             19
#define FLB_LOG_EVENT_TIMESTAMP_VALUE_TYPE               20
#define FLB_LOG_EVENT_LEGACY_TIMESTAMP_VALUE_TYPE        21
#define FLB_LOG_EVENT_FORWARD_V1_TIMESTAMP_VALUE_TYPE    22
#define FLB_LOG_EVENT_FLUENT_BIT_V1_TIMESTAMP_VALUE_TYPE 23
#define FLB_LOG_EVENT_FLUENT_BIT_V2_TIMESTAMP_VALUE_TYPE 24

#define FLB_LOG_EVENT_STRING_MIN_VALUE_TYPE              FLB_LOG_EVENT_STRING_LENGTH_VALUE_TYPE
#define FLB_LOG_EVENT_STRING_MAX_VALUE_TYPE              FLB_LOG_EVENT_FLUENT_BIT_V2_TIMESTAMP_VALUE_TYPE

#define FLB_LOG_EVENT_ROOT                               1
#define FLB_LOG_EVENT_METADATA                           2
#define FLB_LOG_EVENT_BODY                               3

#define FLB_LOG_EVENT_APPEND_UNTIL_TERMINATOR            -1

#define FLB_LOG_EVENT_VALUE_LIST_TERMINATOR() \
            FLB_LOG_EVENT_APPEND_TERMINATOR_VALUE_TYPE

#define FLB_LOG_EVENT_STRING_LENGTH_VALUE(length) \
            FLB_LOG_EVENT_STRING_LENGTH_VALUE_TYPE, \
            length

#define FLB_LOG_EVENT_STRING_BODY_VALUE(buffer, length) \
            FLB_LOG_EVENT_STRING_BODY_VALUE_TYPE, \
            (char *) buffer, \
            length

#define FLB_LOG_EVENT_BINARY_LENGTH_VALUE(length) \
            FLB_LOG_EVENT_BINARY_LENGTH_VALUE_TYPE, \
            length

#define FLB_LOG_EVENT_BINARY_BODY_VALUE(buffer, length) \
            FLB_LOG_EVENT_BINARY_BODY_VALUE_TYPE, \
            (char *) buffer, \
            length

#define FLB_LOG_EVENT_EXT_LENGTH_VALUE(type_, length) \
            FLB_LOG_EVENT_EXT_LENGTH_VALUE_TYPE, \
            type_, \
            length

#define FLB_LOG_EVENT_EXT_BODY_VALUE(buffer, length) \
            FLB_LOG_EVENT_EXT_BODY_VALUE_TYPE, \
            (char *) buffer, \
            length

#define FLB_LOG_EVENT_TIMESTAMP_VALUE(value) \
            FLB_LOG_EVENT_TIMESTAMP_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_LEGACY_TIMESTAMP_VALUE(value) \
            FLB_LOG_EVENT_LEGACY_TIMESTAMP_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_FORWARD_V1_TIMESTAMP_VALUE(value) \
            FLB_LOG_EVENT_FORWARD_V1_TIMESTAMP_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_FLUENT_BIT_V1_TIMESTAMP_VALUE(value) \
            FLB_LOG_EVENT_FLUENT_BIT_V1_TIMESTAMP_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_CHAR_VALUE(value) \
            FLB_LOG_EVENT_CHAR_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_INT8_VALUE(value) \
            FLB_LOG_EVENT_INT8_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_INT16_VALUE(value) \
            FLB_LOG_EVENT_INT16_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_INT32_VALUE(value) \
            FLB_LOG_EVENT_INT32_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_INT64_VALUE(value) \
            FLB_LOG_EVENT_INT64_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_UINT8_VALUE(value) \
            FLB_LOG_EVENT_UINT8_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_UINT16_VALUE(value) \
            FLB_LOG_EVENT_UINT16_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_UINT32_VALUE(value) \
            FLB_LOG_EVENT_UINT32_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_UINT64_VALUE(value) \
            FLB_LOG_EVENT_UINT64_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_DOUBLE_VALUE(value) \
            FLB_LOG_EVENT_DOUBLE_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_BOOLEAN_VALUE(value) \
            FLB_LOG_EVENT_BOOLEAN_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(value) \
            FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE_TYPE, \
            value

#define FLB_LOG_EVENT_MSGPACK_RAW_VALUE(buffer, length) \
            FLB_LOG_EVENT_MSGPACK_RAW_VALUE_TYPE, \
            buffer, \
            length

#define FLB_LOG_EVENT_STRING_VALUE(buffer, length) \
            FLB_LOG_EVENT_STRING_LENGTH_VALUE(length), \
            FLB_LOG_EVENT_STRING_BODY_VALUE(buffer, length)

#define FLB_LOG_EVENT_BINARY_VALUE(buffer, length) \
            FLB_LOG_EVENT_BINARY_LENGTH_VALUE(length), \
            FLB_LOG_EVENT_BINARY_BODY_VALUE(buffer, length)

#define FLB_LOG_EVENT_EXT_VALUE(type_, buffer, length) \
            FLB_LOG_EVENT_EXT_LENGTH_VALUE(type, length), \
            FLB_LOG_EVENT_EXT_BODY_VALUE(buffer, length)

#define FLB_LOG_EVENT_CSTRING_VALUE(buffer) \
            FLB_LOG_EVENT_STRING_VALUE(buffer, strlen(buffer))

struct flb_log_event_encoder {
    int                                         dynamically_allocated;
    char                                       *output_buffer;
    size_t                                      output_length;
    int                                         initialized;

    struct flb_time                             timestamp;
    struct flb_log_event_encoder_dynamic_field  metadata;
    struct flb_log_event_encoder_dynamic_field  body;
    struct flb_log_event_encoder_dynamic_field  root;

    msgpack_packer                              packer;
    msgpack_sbuffer                             buffer;

    int                                         format;
};

int flb_log_event_encoder_init(struct flb_log_event_encoder *context,
                               int format);

struct flb_log_event_encoder *flb_log_event_encoder_create(int format);

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context);

void flb_log_event_encoder_reset(struct flb_log_event_encoder *context);

void flb_log_event_encoder_claim_internal_buffer_ownership(
        struct flb_log_event_encoder *context);

int flb_log_event_encoder_emit_record(struct flb_log_event_encoder *context);
int flb_log_event_encoder_reset_record(struct flb_log_event_encoder *context);
int flb_log_event_encoder_begin_record(struct flb_log_event_encoder *context);
int flb_log_event_encoder_commit_record(struct flb_log_event_encoder *context);
int flb_log_event_encoder_rollback_record(struct flb_log_event_encoder *context);

int flb_log_event_encoder_set_timestamp(
        struct flb_log_event_encoder *context,
        struct flb_time *timestamp);

int flb_log_event_encoder_set_current_timestamp(
        struct flb_log_event_encoder *context);


int flb_log_event_encoder_append_metadata_values(
        struct flb_log_event_encoder *context,
        ssize_t value_count,
        ...);

int flb_log_event_encoder_append_body_values(
        struct flb_log_event_encoder *context,
        ssize_t value_count,
        ...);

int flb_log_event_encoder_append_root_values(
        struct flb_log_event_encoder *context,
        ssize_t value_count,
        ...);

#include <fluent-bit/flb_log_event_encoder_primitives.h>
#include <fluent-bit/flb_log_event_encoder_root_macros.h>
#include <fluent-bit/flb_log_event_encoder_metadata_macros.h>
#include <fluent-bit/flb_log_event_encoder_body_macros.h>

#endif
