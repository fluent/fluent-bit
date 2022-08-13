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

#ifndef FLB_COROUTINE_SCHEDULER_H
#define FLB_COROUTINE_SCHEDULER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_pipe.h>

#include <monkey/mk_core.h>

#define FLB_COROUTINE_STATUS_UNINITIALIZED           0
#define FLB_COROUTINE_STATUS_RUNNING                 1
#define FLB_COROUTINE_STATUS_PAUSED                  2
#define FLB_COROUTINE_STATUS_QUEUED                  3
#define FLB_COROUTINE_STATUS_COLLABORATIVELY_YIELDED 4

struct flb_coro;

struct flb_coroutine_scheduler {
    struct mk_event wakeup_event;
    flb_pipefd_t    wakeup_channels[2];
    struct mk_list  paused_coroutines;
    struct mk_list  queued_coroutines;
    size_t          resumption_limit;
    size_t          resumption_count;
    uint64_t        cycle_number;
    uint64_t        last_wakeup_emission_cycle;
};

struct flb_coroutine_scheduler *flb_coroutine_scheduler_get();

void flb_coroutine_scheduler_set(struct flb_coroutine_scheduler *scheduler);

int flb_coroutine_scheduler_init(struct flb_coroutine_scheduler *scheduler,
                                 size_t resumption_limit);

int flb_coroutine_scheduler_add_event_loop(struct flb_coroutine_scheduler *scheduler,
                                           struct mk_event_loop *event_loop);

int flb_coroutine_scheduler_uninitialize(struct flb_coroutine_scheduler *scheduler);

int flb_coroutine_scheduler_get_coroutine_state(struct flb_coro *coroutine);

int flb_coroutine_scheduler_set_coroutine_state(struct flb_coro *coroutine, 
                                                int state);

int flb_coroutine_scheduler_emit_continuation_signal(struct flb_coroutine_scheduler *scheduler);
int flb_coroutine_scheduler_consume_continuation_signal(struct flb_coroutine_scheduler *scheduler);

struct flb_coro *flb_coroutine_scheduler_fetch_next_enqueued_coroutine();
int flb_coroutine_scheduler_resume_enqueued_coroutines();

// void flb_coro_resume_request_list_init();
// struct mk_list *flb_coro_resume_request_list_get();
// void flb_coro_resume_request_list_set(struct mk_list *list);
// int flb_coro_resume_request_enqueue(struct flb_coro *coro);
// struct flb_coro_resume_request *flb_coro_resume_request_fetch();
// void flb_coro_resume_request_destroy(struct flb_coro_resume_request *request);

#endif /* !FLB_COROUTINE_SCHEDULER_H */
