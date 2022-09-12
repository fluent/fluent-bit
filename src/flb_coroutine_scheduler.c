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

#include <fluent-bit/flb_coroutine_scheduler.h>
#include <fluent-bit/flb_thread_storage.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_coro.h>

static pthread_once_t local_flb_coroutine_scheduler_init = PTHREAD_ONCE_INIT;

FLB_TLS_DEFINE(struct flb_coroutine_scheduler,
               flb_coroutine_scheduler_instance);

static void flb_coroutine_scheduler_init_private()
{
    FLB_TLS_INIT(flb_coroutine_scheduler_instance);
}

static void flb_coroutine_scheduler_tls_init()
{
    pthread_once(&local_flb_coroutine_scheduler_init,
                 flb_coroutine_scheduler_init_private);
}

struct flb_coroutine_scheduler *flb_coroutine_scheduler_get()
{
    flb_coroutine_scheduler_tls_init();

    return FLB_TLS_GET(flb_coroutine_scheduler_instance);
}

void flb_coroutine_scheduler_set(struct flb_coroutine_scheduler *scheduler)
{
    flb_coroutine_scheduler_tls_init();

    FLB_TLS_SET(flb_coroutine_scheduler_instance, scheduler);
}


int flb_coroutine_scheduler_init(struct flb_coroutine_scheduler *scheduler,
                                 size_t resumption_limit)
{
    if (scheduler == NULL) {
        return -1;
    }

    memset(scheduler, 0, sizeof(struct flb_coroutine_scheduler));

    mk_list_init(&scheduler->paused_coroutines);
    mk_list_init(&scheduler->queued_coroutines);

    scheduler->last_wakeup_emission_cycle = -1;
    scheduler->resumption_limit = resumption_limit;

    scheduler->wakeup_channels[0] = -1;
    scheduler->wakeup_channels[1] = -1;

    return 0;
}

int flb_coroutine_scheduler_add_event_loop(struct flb_coroutine_scheduler *scheduler,
                                           struct mk_event_loop *event_loop)
{
    int result;

    if (scheduler == NULL) {
        return -1;
    }

    if (event_loop == NULL) {
        event_loop = flb_engine_evl_get();

        if (event_loop == NULL) {
            return -2;
        }
    }

    result = flb_pipe_create(scheduler->wakeup_channels);

    if (result != 0) {
        return -3;
    }

    flb_pipe_set_nonblocking(scheduler->wakeup_channels[0]);
    flb_pipe_set_nonblocking(scheduler->wakeup_channels[1]);

    MK_EVENT_ZERO(&scheduler->wakeup_event);

    result = mk_event_add(event_loop,
                          scheduler->wakeup_channels[0],
                          FLB_ENGINE_EV_CORO_SCHEDULER,
                          MK_EVENT_READ,
                          &scheduler->wakeup_event);

    if (result) {
        flb_pipe_destroy(scheduler->wakeup_channels);

        scheduler->wakeup_channels[0] = -1;
        scheduler->wakeup_channels[1] = -1;

        return -4;
    }

    return 0;
}

int flb_coroutine_scheduler_uninitialize(struct flb_coroutine_scheduler *scheduler)
{
    if (scheduler == NULL) {
        return -1;
    }

    if (scheduler->wakeup_channels[0] != -1) {
        flb_pipe_destroy(scheduler->wakeup_channels);

        scheduler->wakeup_channels[0] = -1;
        scheduler->wakeup_channels[1] = -1;
    }

    return 0;
}

int flb_coroutine_scheduler_get_coroutine_state(struct flb_coro *coroutine)
{
    return coroutine->state;
}

int flb_coroutine_scheduler_set_coroutine_state(struct flb_coro *coroutine,
                                                int state)
{
    struct flb_coroutine_scheduler *scheduler;
    int                             result;

    scheduler = flb_coroutine_scheduler_get();

    if (scheduler == NULL) {
        return -1;
    }

    if (!mk_list_entry_is_orphan(&coroutine->_head)) {
        mk_list_del(&coroutine->_head);
    }

    /* Coroutines that were explicitly enqueued to be resumed are prepended to
     * the queued_coroutines list and coroutines that have performed a
     * collaborative yield are appended to the list which allows the scheduler
     * to naturally prioritize coroutines that need to be immediately resumed
     * as well as wasting less time iterating collaboratively yielded coroutines
     * that have to be resumed in the current scheduler cycle.
     */

    if (state == FLB_COROUTINE_STATUS_PAUSED) {
        coroutine->yield_cycle = scheduler->cycle_number;

        mk_list_add(&coroutine->_head, &scheduler->paused_coroutines);
    }
    else if (state == FLB_COROUTINE_STATUS_QUEUED) {
        mk_list_prepend(&coroutine->_head, &scheduler->queued_coroutines);
    }
    else if (state == FLB_COROUTINE_STATUS_COLLABORATIVELY_YIELDED) {
        mk_list_append(&coroutine->_head, &scheduler->queued_coroutines);

        flb_coroutine_scheduler_emit_continuation_signal(scheduler);

        coroutine->yield_cycle = scheduler->cycle_number;
    }

    coroutine->state = state;

    return 0;
}

int flb_coroutine_scheduler_emit_continuation_signal(struct flb_coroutine_scheduler *scheduler)
{
    ssize_t result;

    if (scheduler == NULL) {
        scheduler = flb_coroutine_scheduler_get();

        if (scheduler == NULL) {
            return -1;
        }
    }

    if (scheduler->wakeup_channels[0] == -1) {
        return -2;
    }

    if (scheduler->last_wakeup_emission_cycle == scheduler->cycle_number) {
        return -3;
    }

    result = flb_pipe_write_all(scheduler->wakeup_channels[1], ".", 1);

    if (result == -1) {
        return -4;
    }

    scheduler->last_wakeup_emission_cycle = scheduler->cycle_number;

    return 0;
}

int flb_coroutine_scheduler_consume_continuation_signal(struct flb_coroutine_scheduler *scheduler)
{
    char    signal_buffer[1];
    ssize_t result;

    if (scheduler == NULL) {
        scheduler = flb_coroutine_scheduler_get();

        if (scheduler == NULL) {
            return -1;
        }
    }

    if (scheduler->wakeup_channels[0] == -1) {
        return -2;
    }

    if (scheduler->last_wakeup_emission_cycle == scheduler->cycle_number) {
        return -3;
    }

    result = flb_pipe_read_all(scheduler->wakeup_channels[0], signal_buffer, 1);

    if (result == -1) {
        return -4;
    }

    return 0;
}

struct flb_coro *flb_coroutine_scheduler_fetch_next_enqueued_coroutine()
{
    struct flb_coro                *coroutine;
    struct flb_coroutine_scheduler *scheduler;

    scheduler = flb_coroutine_scheduler_get();

    if (scheduler == NULL) {
        return NULL;
    }

    coroutine = NULL;

    if (mk_list_is_empty(&scheduler->queued_coroutines)) {
        coroutine = mk_list_entry_first(&scheduler->queued_coroutines,
                                        struct flb_coro,
                                        _head);
    }

    if (coroutine != NULL) {
        if (coroutine->state == FLB_COROUTINE_STATUS_COLLABORATIVELY_YIELDED) {
            if (coroutine->yield_cycle == scheduler->cycle_number) {
                coroutine = NULL;
            }
        }
    }

    return coroutine;
}

int flb_coroutine_scheduler_resume_enqueued_coroutines()
{
    int                             continuation_required;
    uint64_t                        current_timestamp;
    uint64_t                        start_timestamp;
    uint64_t                        timeslice_end;
    struct flb_coro                *coroutine;
    struct flb_coroutine_scheduler *scheduler;

    scheduler = flb_coroutine_scheduler_get();

    if (scheduler == NULL) {
        return -1;
    }

    scheduler->resumption_count = 0;
    continuation_required = FLB_FALSE;

    timeslice_end = 0;

    if (scheduler->collective_time_slice != FLB_CORO_TIME_SLICE_UNLIMITED) {
        timeslice_end  = flb_time_get_cpu_timestamp();
        timeslice_end += scheduler->collective_time_slice;
    }

    do {
        coroutine = flb_coroutine_scheduler_fetch_next_enqueued_coroutine();

        if (coroutine == NULL) {
            break;
        }

        flb_coro_resume(coroutine);

        scheduler->resumption_count++;

        if (scheduler->resumption_limit != -1) {
            if (scheduler->resumption_count >= scheduler->resumption_limit) {
                continuation_required = FLB_TRUE;
            }
        }

        if (!continuation_required) {
            if (timeslice_end > 0) {
                if (flb_time_get_cpu_timestamp() > timeslice_end) {
                    continuation_required = FLB_TRUE;
                }
            }
        }

        if (continuation_required) {
            printf("EXITING AFTER %d\n", scheduler->resumption_count);
            flb_coroutine_scheduler_emit_continuation_signal(scheduler);

            break;
        }
    } while (1);

    /* This cycle counter is meant to wrap, it's a number because it's not
     * an expensive operation but could very well be a boolean and it would
     * retain its desired properties.
     */

    scheduler->cycle_number = (scheduler->cycle_number + 1) % UINT64_MAX;

    return 0;
}
