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

#ifndef FLB_FLUENT_EVENT_H
#define FLB_FLUENT_EVENT_H

#include <fluent-bit/flb_time.h>
#include <msgpack.h>

typedef enum _flb_fluent_event_lib_type {
    FLB_FLUENT_EVENT_LIB_TYPE_MSGPACK = 1, /* msgpack-c */
    FLB_FLUENT_EVENT_LIB_TYPE_MPACK , /* mpack */
    FLB_FLUENT_EVENT_LIB_TYPE_UNKNOWN,
} flb_fluent_event_lib_type;

struct flb_fluent_record {
    flb_fluent_event_lib_type type;
    union {
        msgpack_object *msgpack;
        mpack_reader_t *mpack;
    }reader;
};

typedef enum _flb_fluent_event_fmt {
    FLB_FLUENT_EVENT_FMT_TIME_RECORD = 1, /* [TIMESTAMP, {RECORD}] */
    FLB_FLUENT_EVENT_FMT_UNKNOWN,
}flb_fluent_event_fmt;

/* 
 * A struct to represent fluent event.
 * https://docs.fluentbit.io/manual/concepts/key-concepts#event-or-record
 */
struct flb_fluent_event {
    flb_fluent_event_fmt format;
    struct flb_time timestamp;
    struct flb_fluent_record record;
    /* TODO: metadata ?*/
};

static inline void flb_fluent_event_set_default(struct flb_fluent_event *event)
{
    event->format = FLB_FLUENT_EVENT_FMT_UNKNOWN;
    event->record.type = FLB_FLUENT_EVENT_LIB_TYPE_UNKNOWN;
}

#endif
