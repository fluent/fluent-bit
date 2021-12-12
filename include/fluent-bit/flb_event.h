/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_EVENT_H
#define FLB_EVENT_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_chunk.h>

/* Event types */
#define FLB_EVENT_TYPE_LOG     FLB_INPUT_CHUNK_TYPE_LOG
#define FLB_EVENT_TYPE_METRIC  FLB_INPUT_CHUNK_TYPE_METRIC

/*
 * The flb_event_chunk structure is a full context used in the output plugins
 * flush callback. It contains the type of records (logs, metrics), the tag,
 * msgpack buffer, it size and a hint of the serialized msgpack events.
 */
struct flb_event_chunk {
    int type;               /* event type */
    flb_sds_t tag;          /* tag associated */
    const void *data;       /* event content */
    size_t size;            /* size of event */
    size_t total_events;    /* total number of serialized events */
};

struct flb_event_chunk *flb_event_chunk_create(int type,
                                               int total_events,
                                               char *tag_buf, int tag_len,
                                               char *buf_data, size_t buf_size);

int flb_event_chunk_update(struct flb_event_chunk *evc,
                           char *buf_data, size_t buf_size);

void flb_event_chunk_destroy(struct flb_event_chunk *evc);

#endif
