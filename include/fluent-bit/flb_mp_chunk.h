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

#ifndef FLB_MP_CHUNK_H
#define FLB_MP_CHUNK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log_event.h>
#include <cfl/cfl.h>

#define FLB_MP_CHUNK_RECORD_ERROR -1  /* Error while retrieving content */
#define FLB_MP_CHUNK_RECORD_OK     0  /* Content retrieved successfully */
#define FLB_MP_CHUNK_RECORD_EOF    1  /* No more content to retrieve */

/* Forward declaration to avoid circular dependencies */
struct flb_condition;

struct flb_mp_chunk_record {
    int modified;
    struct flb_log_event event;
    struct cfl_object *cobj_metadata;
    struct cfl_object *cobj_record;
    struct cfl_object *cobj_group_metadata;
    struct cfl_object *cobj_group_attributes;
    int owns_group_metadata;
    int owns_group_attributes;
    struct cfl_list _head;
};

struct flb_mp_chunk_cobj {
    int total_records;
    struct flb_log_event_encoder *log_encoder;
    struct flb_log_event_decoder *log_decoder;

    struct flb_mp_chunk_record *record_pos;
    struct cfl_list records;

    struct cfl_object *active_group_metadata;
    struct cfl_object *active_group_attributes;

    /* Condition for filtering records during processing */
    struct flb_condition *condition;
};


struct flb_mp_chunk_record *flb_mp_chunk_record_create(struct flb_mp_chunk_cobj *chunk_cobj);

int flb_mp_chunk_cobj_record_destroy(struct flb_mp_chunk_cobj *chunk_cobj,
                                     struct flb_mp_chunk_record *record);
int flb_mp_chunk_cobj_record_next(struct flb_mp_chunk_cobj *chunk_cobj,
                                  struct flb_mp_chunk_record **out_record);

struct flb_mp_chunk_cobj *flb_mp_chunk_cobj_create(struct flb_log_event_encoder *log_encoder,
                                                   struct flb_log_event_decoder *log_decoder);
int flb_mp_chunk_cobj_destroy(struct flb_mp_chunk_cobj *chunk_cobj);

int flb_mp_chunk_cobj_encode(struct flb_mp_chunk_cobj *chunk_cobj, char **out_buf, size_t *out_size);




#endif
