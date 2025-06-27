/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#ifndef CTR_LINK_H
#define CTR_LINK_H

#include <ctraces/ctraces.h>

struct ctrace_link {
	struct ctrace_id *trace_id;       /* the unique traceID    */
    struct ctrace_id *span_id;        /* the unique span ID    */
	cfl_sds_t trace_state;            /* trace_state           */
    struct ctrace_attributes *attr;   /* attributes */
    uint32_t dropped_attr_count;      /* number of attributes that were discarded */
    uint32_t flags;                   /* flags */

    /* --- INTERNAL --- */
    struct cfl_list _head;            /* link to 'struct span->links' list */
};

struct ctrace_link *ctr_link_create(struct ctrace_span *span,
                                    void *trace_id_buf, size_t trace_id_len,
                                    void *span_id_buf, size_t span_id_len);

struct ctrace_link *ctr_link_create_with_cid(struct ctrace_span *span,
                                             struct ctrace_id *trace_id_cid,
					 					     struct ctrace_id *span_id_cid);

int ctr_link_set_trace_state(struct ctrace_link *link, char *trace_state);
int ctr_link_set_attributes(struct ctrace_link *link, struct ctrace_attributes *attr);
void ctr_link_set_dropped_attr_count(struct ctrace_link *link, uint32_t count);
void ctr_link_set_flags(struct ctrace_link *link, uint32_t flags);

void ctr_link_destroy(struct ctrace_link *link);

#endif
