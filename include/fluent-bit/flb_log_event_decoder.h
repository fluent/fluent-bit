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

#ifndef FLB_LOG_EVENT_DECODER_H
#define FLB_LOG_EVENT_DECODER_H

#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event.h>

#include <msgpack.h>


#define FLB_EVENT_DECODER_SUCCESS                        0
#define FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE  -1
#define FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT         -2
#define FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT        -3
#define FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE         -4
#define FLB_EVENT_DECODER_ERROR_WRONG_ROOT_SIZE         -5
#define FLB_EVENT_DECODER_ERROR_WRONG_HEADER_TYPE       -6
#define FLB_EVENT_DECODER_ERROR_WRONG_HEADER_SIZE       -7
#define FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE    -8
#define FLB_EVENT_DECODER_ERROR_WRONG_METADATA_TYPE     -9
#define FLB_EVENT_DECODER_ERROR_WRONG_BODY_TYPE         -10
#define FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE -11
#define FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA       -12

#define FLB_LOG_EVENT_EXPECTED_ROOT_ELEMENT_COUNT        2
#define FLB_LOG_EVENT_EXPECTED_HEADER_ELEMENT_COUNT      2

struct flb_log_event_decoder {
    msgpack_object   *current_group_attributes;
    msgpack_unpacked  unpacked_group_record;
    int               dynamically_allocated;
    msgpack_object  *current_group_metadata;
    msgpack_unpacked  unpacked_empty_map;
    size_t            previous_offset;
    msgpack_unpacked  unpacked_event;
    size_t            record_length;
    const char       *record_base;
    int               initialized;
    msgpack_object   *empty_map;
    const char       *buffer;
    size_t            offset;
    size_t            length;
    int               last_result;
    int               read_groups;
};

void flb_log_event_decoder_reset(struct flb_log_event_decoder *context,
                                 char *input_buffer,
                                 size_t input_length);

int flb_log_event_decoder_read_groups(struct flb_log_event_decoder *context,
                                      int read_groups);

int flb_log_event_decoder_init(struct flb_log_event_decoder *context,
                               char *input_buffer,
                               size_t input_length);

struct flb_log_event_decoder *flb_log_event_decoder_create(char *input_buffer,
                                                           size_t input_length);

void flb_log_event_decoder_destroy(struct flb_log_event_decoder *context);

int flb_log_event_decoder_decode_timestamp(msgpack_object *input,
                                           struct flb_time *output);

int flb_event_decoder_decode_object(struct flb_log_event_decoder *context,
                                    struct flb_log_event *event,
                                    msgpack_object *input);
int flb_log_event_decoder_get_last_result(struct flb_log_event_decoder *context);
int flb_log_event_decoder_next(struct flb_log_event_decoder *context,
                               struct flb_log_event *record);

const char *flb_log_event_decoder_get_error_description(int error_code);

int flb_log_event_decoder_get_record_type(struct flb_log_event *event, int32_t *type);

#endif
