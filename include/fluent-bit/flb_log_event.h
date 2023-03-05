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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mp.h>
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

#define FLB_EVENT_ENCODER_SUCCESS                        0
#define FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT         -1
#define FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT        -2
#define FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE   -3

#define FLB_LOG_EVENT_EXPECTED_ROOT_ELEMENT_COUNT        2
#define FLB_LOG_EVENT_EXPECTED_HEADER_ELEMENT_COUNT      2

#define FLB_LOG_EVENT_FORMAT_UNKNOWN                     0
#define FLB_LOG_EVENT_FORMAT_DEFAULT                     FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2
#define FLB_LOG_EVENT_FORMAT_FORWARD_LEGACY              1
#define FLB_LOG_EVENT_FORMAT_FORWARD                     2
#define FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V1               FLB_LOG_EVENT_FORMAT_FORWARD
#define FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2               4

#define FLB_LOG_EVENT_ENCODER_COMPONENT_TYPE_CALLBACK       0
#define FLB_LOG_EVENT_ENCODER_COMPONENT_TYPE_MSGPACK_OBJECT 1
#define FLB_LOG_EVENT_ENCODER_COMPONENT_TYPE_MSGPACK_BUFFER 2

struct flb_log_event {
    msgpack_object  *raw_timestamp;
    struct flb_time  timestamp;
    msgpack_object  *metadata;
    int              format;
    msgpack_object  *body;
};

struct flb_log_event_decoder {
    int               dynamically_allocated;
    msgpack_unpacked  unpacked_empty_map;
    msgpack_unpacked  unpacked_event;
    msgpack_object   *empty_map;
    const char       *buffer;
    size_t            offset;
    size_t            length;
};


struct flb_log_event_encoder_dynamic_field {
    int                      initialized;
    size_t                   entry_count;
    size_t                   data_offset;
    msgpack_packer           packer;
    msgpack_sbuffer          buffer;
    char                    *data;
    size_t                   size;
    int                      type;
};

struct flb_log_event_encoder {
    int                                         dynamically_allocated;
    char                                       *output_buffer;
    size_t                                      output_length;

    struct flb_time                             timestamp;
    struct flb_log_event_encoder_dynamic_field  metadata;
    struct flb_log_event_encoder_dynamic_field  body;

    msgpack_packer                              packer;
    msgpack_sbuffer                             buffer;

    int                                         format;
};

struct flb_log_event_encoder_raw_msgpack_components {
     const char      *metadata_buffer;
     size_t           metadata_length;
     const char      *body_buffer;
     size_t           body_length;
     struct flb_time *timestamp;
};

struct flb_log_event_encoder_msgpack_components {
     struct flb_time *timestamp;
     msgpack_object  *metadata;
     msgpack_object  *body;
};

typedef int (*flb_event_encoder_callback)(struct flb_log_event_encoder *context,
                                          void *user_data);

void flb_log_event_decoder_reset(struct flb_log_event_decoder *context,
                                 char *input_buffer,
                                 size_t input_length);

int flb_log_event_decoder_init(struct flb_log_event_decoder *context,
                               char *input_buffer,
                               size_t input_length);

struct flb_log_event_decoder *flb_log_event_decoder_create(char *input_buffer,
                                                           size_t input_length);

void flb_log_event_decoder_destroy(struct flb_log_event_decoder *context);

int flb_event_decoder_mock_event(struct flb_log_event_decoder *context,
                                 struct flb_log_event *event,
                                 msgpack_object *input);

int flb_event_decoder_decode_object(struct flb_log_event_decoder *context,
                                    struct flb_log_event *event,
                                    msgpack_object *input);

int flb_log_event_decoder_next(struct flb_log_event_decoder *context,
                               struct flb_log_event *record);

void flb_log_event_encoder_reset(struct flb_log_event_encoder *context);

int flb_log_event_encoder_init(struct flb_log_event_encoder *context,
                               int format);

struct flb_log_event_encoder *flb_log_event_encoder_create(int format);

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context);

void flb_log_event_encoder_claim_internal_buffer_ownership(
        struct flb_log_event_encoder *context);

int flb_log_event_encoder_pack_timestamp(struct flb_log_event_encoder *context,
                                         struct flb_time *timestamp);

int flb_log_event_encoder_pack_msgpack_object(struct flb_log_event_encoder *context,
                                              msgpack_object *value);

int flb_log_event_encoder_pack_msgpack_raw_buffer(struct flb_log_event_encoder *context,
                                                  const char *buffer,
                                                  size_t length);

int flb_log_event_encoder_pack_raw_msgpack_or_empty_object(
    struct flb_log_event_encoder *context,
    const char *buffer,
    size_t length,
    int placeholder_type);

int flb_log_event_encoder_pack_msgpack_object_or_empty_object(
    struct flb_log_event_encoder *context,
    msgpack_object *object,
    int placeholder_type);

int flb_log_event_encoder_pack_array(struct flb_log_event_encoder *context,
                                     size_t element_count);

int flb_log_event_encoder_pack_map(struct flb_log_event_encoder *context,
                                   size_t element_count);

int flb_log_event_encoder_pack_string_length(
    struct flb_log_event_encoder *context,
    size_t length);

int flb_log_event_encoder_pack_string_body(
    struct flb_log_event_encoder *context,
    char *value,
    size_t length);

int flb_log_event_encoder_pack_string_with_length(
    struct flb_log_event_encoder *context,
    char *value,
    size_t length);

int flb_log_event_encoder_pack_string(
    struct flb_log_event_encoder *context,
    char *value);

int flb_log_event_encoder_pack_sds(
    struct flb_log_event_encoder *context,
    char *value);

int flb_log_event_encoder_pack_uint64(
    struct flb_log_event_encoder *context,
    uint64_t value);

int flb_log_event_encoder_pack_uint32(
    struct flb_log_event_encoder *context,
    uint32_t value);

int flb_log_event_encoder_pack_uint16(
    struct flb_log_event_encoder *context,
    uint16_t value);

int flb_log_event_encoder_pack_uint8(
    struct flb_log_event_encoder *context,
    uint8_t value);

int flb_log_event_encoder_pack_int64(
    struct flb_log_event_encoder *context,
    int64_t value);

int flb_log_event_encoder_pack_int32(
    struct flb_log_event_encoder *context,
    int32_t value);

int flb_log_event_encoder_pack_int16(
    struct flb_log_event_encoder *context,
    int16_t value);

int flb_log_event_encoder_pack_int8(
    struct flb_log_event_encoder *context,
    int8_t value);

int flb_log_event_encoder_pack_raw_msgpack(
    struct flb_log_event_encoder *context,
    char *value,
    size_t length);

int flb_log_event_encoder_append(struct flb_log_event_encoder *context,
                                 flb_event_encoder_callback timestamp_callback,
                                 flb_event_encoder_callback metadata_callback,
                                 flb_event_encoder_callback body_callback,
                                 void *user_data);

int flb_log_event_encoder_append_ex(struct flb_log_event_encoder *context,
                                    void *timestamp_buffer,
                                    size_t timestamp_length,
                                    int timestamp_type,
                                    void *metadata_buffer,
                                    size_t metadata_length,
                                    int metadata_type,
                                    void *body_buffer,
                                    size_t body_length,
                                    int body_type,
                                    void *user_data);

int flb_log_event_encoder_append_msgpack_object(struct flb_log_event_encoder *context,
                                                struct flb_time *timestamp,
                                                msgpack_object *metadata,
                                                msgpack_object *body);

int flb_log_event_encoder_append_msgpack_raw(struct flb_log_event_encoder *context,
                                             struct flb_time *timestamp,
                                             const char *metadata_buffer,
                                             size_t metadata_length,
                                             const char *body_buffer,
                                             size_t body_length);


int flb_log_event_encoder_record_reset(struct flb_log_event_encoder *context);
int flb_log_event_encoder_record_rollback(struct flb_log_event_encoder *context);
int flb_log_event_encoder_record_start(struct flb_log_event_encoder *context);
int flb_log_event_encoder_record_commit(struct flb_log_event_encoder *context);
int flb_log_event_encoder_record_timestamp_set(struct flb_log_event_encoder *context,
                                               struct flb_time *timestamp);

int flb_log_event_encoder_record_metadata_append_string(struct flb_log_event_encoder *context,
                                                        char *value);

int flb_log_event_encoder_record_metadata_append_msgpack_object(struct flb_log_event_encoder *context,
                                                                msgpack_object *value);


int flb_log_event_encoder_record_metadata_append_msgpack_raw(struct flb_log_event_encoder *context,
                                                             char *value_buffer,
                                                             size_t value_size);

int flb_log_event_encoder_record_body_append_string(struct flb_log_event_encoder *context,
                                                    char *value);

int flb_log_event_encoder_record_body_append_uint64(struct flb_log_event_encoder *context,
                                                    uint64_t value);

int flb_log_event_encoder_record_body_append_msgpack_object(struct flb_log_event_encoder *context,
                                                            msgpack_object *value);

int flb_log_event_encoder_record_body_append_msgpack_raw(struct flb_log_event_encoder *context,
                                                         char *value_buffer,
                                                         size_t value_size);

void flb_log_event_encoder_dynamic_field_append(
    struct flb_log_event_encoder_dynamic_field *field);

void flb_log_event_encoder_dynamic_field_flush(
    struct flb_log_event_encoder_dynamic_field *field);

int flb_log_event_encoder_dynamic_field_reset(
    struct flb_log_event_encoder_dynamic_field *field);

int flb_log_event_encoder_dynamic_field_init(
    struct flb_log_event_encoder_dynamic_field *field,
    int type);

void flb_log_event_encoder_dynamic_field_destroy(
    struct flb_log_event_encoder_dynamic_field *field);

static inline int flb_msgpack_dump(char *buffer, size_t length)
{
    msgpack_unpacked context;
    size_t           offset;
    int              result;

    offset = 0;

    msgpack_unpacked_init(&context);

    result = msgpack_unpack_next(&context, buffer, length, &offset);

    printf("\n\nDUMPING %p (%zu)\n\n", buffer, length);

    if (result == MSGPACK_UNPACK_SUCCESS) {
        msgpack_object_print(stdout, context.data);
        printf("\n\n");
    }
    else {
        printf("MSGPACK ERROR %d\n\n", result);
    }

    // flb_hex_dump(buffer, length, 40);
    // printf("\n\n");

    msgpack_unpacked_destroy(&context);

    return result;
}

#endif
