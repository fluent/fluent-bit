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

#ifndef FLB_EVENT_LOOP_H
#define FLB_EVENT_LOOP_H

#include <monkey/mk_core/mk_event.h>
#include <fluent-bit/flb_bucket_queue.h>
#include <fluent-bit/flb_log.h>

static inline void flb_event_load_bucket_queue_event(struct flb_bucket_queue *bktq,
                                                    struct mk_event *event)
{
    if (event->_priority_head.prev == NULL) { /* not in bktq */
        flb_bucket_queue_add(bktq, &event->_priority_head, event->priority);
    }
}

/* Priority queue utility */
static inline void flb_event_load_bucket_queue(struct flb_bucket_queue *bktq,
                                              struct mk_event_loop *evl)
{
    struct mk_event *event;
    mk_event_foreach(event, evl) {
        if (event->status != MK_EVENT_NONE) { /* not deleted event */
            flb_event_load_bucket_queue_event(bktq, event);
        }
    }
}

/* Accommadate inject */
static inline void flb_event_load_injected_events(struct flb_bucket_queue *bktq,
                                    struct mk_event_loop *evl,
                                    int n_events_initial)
{
    struct mk_event *event;
    int i;

    if ( evl->n_events < n_events_initial) {
        flb_error("[flb_event_loop] event(s) removed from ready list. "
                  "This should never happen");
        return;
    }

    /* Some events have been added through mk_event_inject */
    if (evl->n_events > n_events_initial) {
        i = 0;
        mk_event_foreach(event, evl) {
            if (i >= n_events_initial) {
                flb_event_load_bucket_queue_event(bktq, event);
            }
            ++i;
        }
    }
}

#define flb_event_priority_live_foreach(event, bktq, evl, max_iter)                     \
    int __flb_event_priority_live_foreach_iter = 0;                                     \
    int __flb_event_priority_live_foreach_n_events = evl->n_events;                     \
    for (                                                                               \
        /* init */                                                                      \
        flb_event_load_bucket_queue(bktq, evl);                                         \
                                                                                        \
        /* condition */                                                                 \
        (__flb_event_priority_live_foreach_iter < max_iter || max_iter == -1)           \
        && (NULL != (                                                                   \
            event = flb_bucket_queue_find_min(bktq)                                     \
                    ? mk_list_entry(flb_bucket_queue_pop_min(bktq),                     \
                                    struct mk_event,                                    \
                                    _priority_head)                                     \
                    : NULL                                                              \
        ));                                                                             \
                                                                                        \
        /* update */                                                                    \
        ++__flb_event_priority_live_foreach_iter,                                       \
        flb_event_load_injected_events(bktq,                                            \
                                       evl,                                             \
                                       __flb_event_priority_live_foreach_n_events),     \
        mk_event_wait_2(evl, 0),                                                        \
        __flb_event_priority_live_foreach_n_events = evl->n_events,                     \
        flb_event_load_bucket_queue(bktq, evl)                                          \
    )

#endif /* !FLB_EVENT_LOOP_H */
