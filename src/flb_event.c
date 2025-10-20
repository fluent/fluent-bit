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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_sds.h>
struct flb_event_chunk *flb_event_chunk_create(int type,
                                               int total_events,
                                               char *tag_buf, int tag_len,
                                               char *buf_data, size_t buf_size)
{
    struct flb_event_chunk *evc;

    /* event chunk context */
    evc = flb_malloc(sizeof(struct flb_event_chunk));
    if (!evc) {
        flb_errno();
        return NULL;
    }

    /* create a copy of the tag */
    evc->tag = flb_sds_create_len(tag_buf, tag_len);
    if (!evc->tag) {
        flb_free(evc);
        return NULL;
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    evc->trace = NULL;
#endif

    evc->type = type;
    evc->data = buf_data;
    evc->size = buf_size;
    evc->total_events = total_events;

    return evc;
}

/* Update the buffer reference */
int flb_event_chunk_update(struct flb_event_chunk *evc,
                           char *buf_data, size_t buf_size)
{
    evc->data = buf_data;
    evc->size = buf_size;

    return 0;
}

void flb_event_chunk_destroy(struct flb_event_chunk *evc)
{
    if (!evc) {
        return;
    }

    if (evc->tag) {
        flb_sds_destroy(evc->tag);
    }
    flb_free(evc);
}
