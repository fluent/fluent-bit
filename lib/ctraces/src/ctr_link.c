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

#include <ctraces/ctraces.h>

struct ctrace_link *ctr_link_create(struct ctrace_span *span,
                                    void *trace_id_buf, size_t trace_id_len,
                                    void *span_id_buf, size_t span_id_len)
{
    struct ctrace_link *link;

    link = calloc(1, sizeof(struct ctrace_link));
    if (!link) {
        ctr_errno();
        return NULL;
    }

    /* trace_id */
    if (trace_id_buf && trace_id_len > 0) {
        link->trace_id = ctr_id_create(trace_id_buf, trace_id_len);
        if (!link->trace_id) {
            free(link);
            return NULL;
        }
    }

    /* span_id */
    if (span_id_buf && span_id_len > 0) {
        link->span_id = ctr_id_create(span_id_buf, span_id_len);
        if (!link->span_id) {
            ctr_id_destroy(link->trace_id);
            free(link);
            return NULL;
        }
    }

    cfl_list_add(&link->_head, &span->links);
    return link;
}

struct ctrace_link *ctr_link_create_with_cid(struct ctrace_span *span,
                                             struct ctrace_id *trace_id_cid,
                                             struct ctrace_id *span_id_cid)
{
    size_t trace_id_len = 0;
    size_t span_id_len = 0;
    void *trace_id_buf = NULL;
    void *span_id_buf = NULL;

    if (trace_id_cid) {
        trace_id_buf = ctr_id_get_buf(trace_id_cid);
        trace_id_len = ctr_id_get_len(trace_id_cid);
    }

    if (span_id_cid) {
        span_id_buf = ctr_id_get_buf(span_id_cid);
        span_id_len = ctr_id_get_len(span_id_cid);
    }

    return ctr_link_create(span, trace_id_buf, trace_id_len, span_id_buf, span_id_len);
}

int ctr_link_set_trace_state(struct ctrace_link *link, char *trace_state)
{
    if (!link || !trace_state) {
        return -1;
    }

    link->trace_state = cfl_sds_create(trace_state);
    if (!link->trace_state) {
        return -1;
    }

    return 0;
}

int ctr_link_set_attributes(struct ctrace_link *link, struct ctrace_attributes *attr)
{
    if (!attr) {
        return -1;
    }

    link->attr = attr;
    return 0;
}

void ctr_link_set_dropped_attr_count(struct ctrace_link *link, uint32_t count)
{
    link->dropped_attr_count = count;
}

void ctr_link_set_flags(struct ctrace_link *link, uint32_t flags)
{
    link->flags = flags;
}

void ctr_link_destroy(struct ctrace_link *link)
{
    if (link->trace_id) {
        ctr_id_destroy(link->trace_id);
    }

    if (link->span_id) {
        ctr_id_destroy(link->span_id);
    }

    if (link->trace_state) {
        cfl_sds_destroy(link->trace_state);
    }

    if (link->attr) {
        ctr_attributes_destroy(link->attr);
    }

    cfl_list_del(&link->_head);
    free(link);
}














