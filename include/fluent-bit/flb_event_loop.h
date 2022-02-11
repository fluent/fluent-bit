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

/* priority queue utility */
static inline void flb_event_load_bucket_queue(struct mk_event *event,
                                      struct flb_bucket_queue *bktq,
                                      struct mk_event_loop *evl)
{
    mk_event_foreach(event, evl) {
        if (event->_priority_head.prev == NULL) {
            flb_bucket_queue_add(bktq, &event->_priority_head, event->priority);
        }
    }
}

#define flb_event_priority_live_foreach(event, bktq, evl, max_iter)                     \
    int __flb_event_priority_live_foreach_iter;                                         \
    for (                                                                               \
        /* init */                                                                      \
        __flb_event_priority_live_foreach_iter = 0,                                     \
        flb_event_load_bucket_queue(event, bktq, evl),                                  \
        event = flb_bucket_queue_find_min(bktq) ?                                       \
                mk_list_entry(                                                          \
                    flb_bucket_queue_pop_min(bktq), struct mk_event, _priority_head) :  \
                NULL;                                                                   \
                                                                                        \
        /* condition */                                                                 \
        event != NULL &&                                                                \
        (__flb_event_priority_live_foreach_iter < max_iter || max_iter == -1);          \
                                                                                        \
        /* update */                                                                    \
        ++__flb_event_priority_live_foreach_iter,                                       \
        mk_event_wait_2(evl, 0),                                                        \
        flb_event_load_bucket_queue(event, bktq, evl),                                  \
        event = flb_bucket_queue_find_min(bktq) ?                                       \
                mk_list_entry(                                                          \
                    flb_bucket_queue_pop_min(bktq), struct mk_event, _priority_head) :  \
                NULL                                                                    \
    )

#endif /* !FLB_EVENT_LOOP_H */
