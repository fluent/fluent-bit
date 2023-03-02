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

#ifndef FLB_LOG_EVENT_H
#define FLB_LOG_EVENT_H

#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#define FLB_EVENT_DECODER_SUCCESS                        0
#define FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT         -1
#define FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT        -2
#define FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE         -3
#define FLB_EVENT_DECODER_ERROR_WRONG_ROOT_SIZE         -4
#define FLB_EVENT_DECODER_ERROR_WRONG_HEADER_TYPE       -5
#define FLB_EVENT_DECODER_ERROR_WRONG_HEADER_SIZE       -6
#define FLB_EVENT_DECODER_ERROR_WRONG_BODY_TYPE         -7
#define FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE -8

#define FLB_EVENT_ENCODER_SUCCESS                        0
#define FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT         -1
#define FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE   -2

#define FLB_LOG_EVENT_EXPECTED_ROOT_ELEMENT_COUNT   2
#define FLB_LOG_EVENT_EXPECTED_HEADER_ELEMENT_COUNT 2

struct flb_log_event {
    msgpack_object  *raw_timestamp;
    struct flb_time  timestamp;
    msgpack_object  *metadata;
    msgpack_object  *body;
};

struct flb_log_event_decoder {
    msgpack_unpacked  unpacked;
    const char       *buffer;
    size_t            offset;
    size_t            length;
};

struct flb_log_event_encoder {
    char           *output_buffer;
    size_t          output_length;
    msgpack_packer  packer;
    msgpack_sbuffer buffer;
};

typedef int (*flb_event_encoder_callback)(struct flb_log_event_encoder *context,
                                          void *user_data);

int flb_event_decoder_verify_entry(struct flb_log_event_decoder *context);

int flb_event_decoder_fetch_header(struct flb_log_event_decoder *context,
                                   msgpack_object **header);

int flb_event_decoder_fetch_timestamp(struct flb_log_event_decoder *context,
                                      msgpack_object **timestamp);

int flb_event_decoder_fetch_metadata(struct flb_log_event_decoder *context,
                                     msgpack_object **metadata);

int flb_event_decoder_fetch_body(struct flb_log_event_decoder *context,
                                 msgpack_object **body);

struct flb_log_event_decoder *flb_log_event_decoder_create(
    const char *input_buffer,
    size_t input_length);

void flb_log_event_decoder_destroy(struct flb_log_event_decoder *context);

int flb_log_event_decoder_next(struct flb_log_event_decoder *context,
                               struct flb_log_event *record);

struct flb_log_event_encoder *flb_log_event_encoder_create();

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context);

int flb_log_event_encoder_current_timestamp_callback(
    struct flb_log_event_encoder *context,
    void *user_data);

int flb_log_event_encoder_empty_metadata_callback(
    struct flb_log_event_encoder *context,
    void *user_data);

int flb_log_event_encoder_empty_body_callback(
    struct flb_log_event_encoder *context,
    void *user_data);

int flb_log_event_encoder_append_ex(struct flb_log_event_encoder *context,
                                    flb_event_encoder_callback timestamp_callback,
                                    flb_event_encoder_callback metadata_callback,
                                    flb_event_encoder_callback body_callback,
                                    void *user_data);
#endif
