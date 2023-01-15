/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#ifndef FLB_EVENT_DECODER_H
#define FLB_EVENT_DECODER_H

#include <msgpack.h>
#include <mpack/mpack.h>


#include <fluent-bit/flb_time.h>
#include <msgpack.h>

typedef enum _flb_event_lib_type {
    FLB_EVENT_LIB_TYPE_MSGPACK = 1, /* msgpack-c */
    FLB_EVENT_LIB_TYPE_MPACK , /* mpack */
    FLB_EVENT_LIB_TYPE_UNKNOWN,
} flb_event_lib_type;

struct flb_fluent_record {
    flb_event_lib_type type;
    union {
        msgpack_object *msgpack;
        mpack_reader_t *mpack;
    }reader;
};

typedef enum _flb_event_fmt {
    FLB_EVENT_FMT_TIME_RECORD = 1, /* [TIMESTAMP, {RECORD}] */
    FLB_EVENT_FMT_UNKNOWN,
}flb_event_fmt;

/* 
 * A struct to represent fluent event.
 * https://docs.fluentbit.io/manual/concepts/key-concepts#event-or-record
 */
struct flb_event {
    flb_event_fmt format;
    struct flb_time timestamp;
    struct flb_fluent_record record;
    /* TODO: metadata ?*/
};

static inline void flb_event_set_default(struct flb_event *event)
{
    event->format = FLB_EVENT_FMT_UNKNOWN;
    event->record.type = FLB_EVENT_LIB_TYPE_UNKNOWN;
}


struct flb_event_decoder_msgpack {
    msgpack_unpacked upk;
};

struct flb_event_decoder_mpack {
    mpack_reader_t reader;
};

struct flb_event_decoder {
    flb_event_lib_type type;
    size_t offset;
    void *raw_data;
    size_t raw_data_size;
    union {
        struct flb_event_decoder_msgpack msgpack;
        struct flb_event_decoder_mpack mpack;
    }decoder;
};

/* decoder option */
#define FLB_EVENT_DECODER_OPT_USE_MPACK (1<<1)

struct flb_event_decoder *flb_event_decoder_create(void *input_buf, size_t input_size, int decoder_opt);
int flb_event_decoder_destroy(struct flb_event_decoder *dec);
int flb_event_decoder_next(struct flb_event_decoder *dec,
                                  struct flb_event *event);
int flb_event_decoder_reuse(struct flb_event_decoder *dec, void *input_buf, size_t input_size);
#endif
