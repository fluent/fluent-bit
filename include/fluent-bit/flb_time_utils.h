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

#ifndef FLB_TIME_UTILS_H
#define FLB_TIME_UTILS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_scheduler.h>

static void flb_time_thread_wakeup(struct flb_config *config, void *data)
{
    (void) config;
    struct flb_coro *th;

    th = (struct flb_coro *) data;
    flb_coro_resume(th);
}

/*
 * Sleep running thread for 'ms' (milliseconds). This function assume
 * that's running in a co-routine.
 *
 * Internally it creates a timer and once the signal gets into the
 * event loop after expiration time, this function resume.
 *
 * A context that invokes flb_time_sleep() will resume upon an
 * internal call to flb_time_thread_wakeup().
 */
static FLB_INLINE void flb_time_sleep(int ms)
{
    int ret;
    struct flb_coro *coro;
    struct flb_sched *sched;

    coro = flb_coro_get();
    if (!coro) {
        flb_error("[thread] invalid context for thread_sleep()");
        return;
    }

    /* Get the scheduler context */
    sched = flb_sched_ctx_get();
    assert(sched != NULL);

    ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_ONESHOT,
                                    ms, flb_time_thread_wakeup, coro, NULL);
    if (ret == -1) {
        return;
    }

    flb_coro_yield(coro, FLB_FALSE);
}

#endif
