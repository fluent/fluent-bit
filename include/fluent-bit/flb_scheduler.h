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

#ifndef FLB_SCHEDULER_H
#define FLB_SCHEDULER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_output.h>

/* Sched contstants */
#define FLB_SCHED_CAP            2000
#define FLB_SCHED_BASE           5
#define FLB_SCHED_REQUEST_FRAME  10

/* Timer types */
#define FLB_SCHED_TIMER_REQUEST     1  /* timerfd             */
#define FLB_SCHED_TIMER_FRAME       2  /* timer frame checker */
#define FLB_SCHED_TIMER_CB_ONESHOT  3  /* one-shot callback timer  */
#define FLB_SCHED_TIMER_CB_PERM     4  /* permanent callback timer */

struct flb_sched;

/*
 * A sched timer struct belongs to an event triggered by the scheduler. This
 * is a generic type and keeps two fields as a reference for further
 * handling:
 *
 * - type: event type used to route to the proper handler
 * - data: opaque data type used by the target handler
 */
struct flb_sched_timer {
    struct mk_event event;
    int active;
    int type;
    void *data;
    struct flb_sched *sched;

    /*
     * Custom timer specific data:
     *
     * - timer_fd = timer file descriptor
     * - cb       = callback to be triggerd upon expiration
     */
    int timer_fd;
    void (*cb)(struct flb_config *, void *);

    /* Parent context */
    struct flb_config *config;

    /* link to flb_sched->timers */
    struct mk_list _head;
};

/* Struct representing a FLB_SCHED_TIMER_REQUEST */
struct flb_sched_request {
    flb_pipefd_t fd;
    time_t created;
    time_t timeout;
    void *data;
    struct flb_sched_timer *timer; /* parent timer linked from */
    struct mk_list _head;          /* link to flb_sched->[requests|wait] */
};

/* Scheduler context */
struct flb_sched {

    /*
     * Scheduler lists:
     *
     * The scheduler is used to issue 'retries' of flush requests when these
     * cannot be processed and the output plugins ask for a retry.
     *
     * If a retry have not reached a limit and is allowed, it needs to be
     * queued:
     *
     *  - For retries that will happen within the next 60 seconds, they are
     *    placed in the 'requests' list and a timeout is registered with
     *    the operating system (timerfd).
     *
     *  - For retries that will happen 'after' 60 seconds, they are queued
     *    into the requests_wait' list. They stay there until their
     *    flush time happens within the next 60 seconds, so they are moved
     *    to the sched_requests list and a further timeout is created.
     */
    struct mk_list requests;
    struct mk_list requests_wait;

    /* Timers: list of timers for different purposes */
    struct mk_list timers;

    /*
     * Timers_Drop: list of invalidated timers that needs to
     * be free()d once the event loop finish the cycle.
     */
    struct mk_list timers_drop;

    /* Frame timer context */
    flb_pipefd_t frame_fd;

    struct mk_event_loop *evl;
    struct flb_config *config;
};

int flb_sched_request_create(struct flb_config *config,
                             void *data, int tries);
int flb_sched_request_destroy(struct flb_sched_request *req);
int flb_sched_event_handler(struct flb_config *config, struct mk_event *event);

struct flb_sched *flb_sched_create(struct flb_config *config,
                                   struct mk_event_loop *evl);

int flb_sched_destroy(struct flb_sched *sched);

struct flb_sched_timer *flb_sched_timer_create(struct flb_sched *sched);
int flb_sched_timer_destroy(struct flb_sched_timer *timer);

int flb_sched_request_invalidate(struct flb_config *config, void *data);

int flb_sched_timer_cb_create(struct flb_sched *sched, int type, int ms,
                              void (*cb)(struct flb_config *, void *),
                              void *data, struct flb_sched_timer **out_timer);
int flb_sched_timer_cb_disable(struct flb_sched_timer *timer);
int flb_sched_timer_cb_destroy(struct flb_sched_timer *timer);
void flb_sched_timer_invalidate(struct flb_sched_timer *timer);
int flb_sched_timer_cleanup(struct flb_sched *sched);
int flb_sched_retry_now(struct flb_config *config, 
                        struct flb_task_retry *retry);

/* Sched context api for multithread environment */
void flb_sched_ctx_init();
struct flb_sched *flb_sched_ctx_get();
void flb_sched_ctx_set(struct flb_sched *sched);

#endif
