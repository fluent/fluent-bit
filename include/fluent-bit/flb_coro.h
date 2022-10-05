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

#ifndef FLB_CORO_H
#define FLB_CORO_H

/* Required by OSX */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_coroutine_scheduler.h>

#include <monkey/mk_core.h>

#include <stdlib.h>
#include <limits.h>
#include <libco.h>

#ifdef FLB_HAVE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct flb_coro {
#ifdef FLB_HAVE_VALGRIND
    unsigned int valgrind_stack_id;
#endif

    /* libco 'contexts' */
    cothread_t caller;
    cothread_t callee;

    void *data;

    int state;
    uint64_t time_slice_backup;
    uint64_t time_slice;
    uint64_t resume_time;
    uint64_t yield_cycle;
    struct mk_list _head;
};

#ifdef FLB_CORO_STACK_SIZE
#define FLB_CORO_STACK_SIZE_BYTE      FLB_CORO_STACK_SIZE
#else
#define FLB_CORO_STACK_SIZE_BYTE      ((3 * PTHREAD_STACK_MIN) / 2)
#endif

#define FLB_CORO_DATA(coro)      (((char *) coro) + sizeof(struct flb_coro))

uint64_t flb_time_get_cpu_timestamp();

static FLB_INLINE int flb_coro_enqueue(struct flb_coro *coro)
{
    return flb_coroutine_scheduler_set_coroutine_state(coro, 
                                                       FLB_COROUTINE_STATUS_QUEUED);
}

static FLB_INLINE void flb_coro_disable_time_slice_limit(struct flb_coro *coro)
{
    if (coro->time_slice != FLB_TIMESLICE_UNLIMITED) {
        coro->time_slice_backup = coro->time_slice;
        coro->time_slice = FLB_TIMESLICE_UNLIMITED;
    }
}

static FLB_INLINE void flb_coro_restore_time_slice_limit(struct flb_coro *coro)
{
    if (coro->time_slice == FLB_TIMESLICE_UNLIMITED) {
        coro->time_slice = coro->time_slice_backup;
    }
}

static FLB_INLINE void flb_coro_set_time_slice_limit(struct flb_coro *coro, uint64_t time_slice)
{
    coro->time_slice = time_slice;
}

static FLB_INLINE void flb_coro_collab_yield(struct flb_coro *coro, int force)
{
    uint64_t elapsed_time;
    uint64_t current_time;
    int      yield_needed;

    yield_needed = force;

    if (!yield_needed) {
        if (coro->time_slice != FLB_TIMESLICE_UNLIMITED) {
            current_time = flb_time_get_cpu_timestamp();
            elapsed_time = current_time - coro->resume_time;

            if (elapsed_time >= coro->time_slice) {
                yield_needed = FLB_TRUE;
            }
        }
    }

    if (yield_needed) {
        flb_coroutine_scheduler_set_coroutine_state(coro,
                                                    FLB_COROUTINE_STATUS_COLLABORATIVELY_YIELDED);

        co_switch(coro->caller);
    }
}

static FLB_INLINE void flb_coro_yield(struct flb_coro *coro, int ended)
{
    flb_coroutine_scheduler_set_coroutine_state(coro, 
                                                FLB_COROUTINE_STATUS_PAUSED);

    co_switch(coro->caller);
}

static FLB_INLINE void flb_coro_destroy(struct flb_coro *coro)
{
    flb_trace("[coro] destroy coroutine=%p data=%p", coro,
              FLB_CORO_DATA(coro));

#ifdef FLB_HAVE_VALGRIND
    VALGRIND_STACK_DEREGISTER(coro->valgrind_stack_id);
#endif

    flb_coroutine_scheduler_set_coroutine_state(coro, 
                                                FLB_COROUTINE_STATUS_UNINITIALIZED);

    if (coro->callee != NULL) {
        co_delete(coro->callee);
    }

    flb_free(coro);
}

#define flb_coro_return(th) co_switch(th->caller)

void flb_coro_init();
void flb_coro_thread_init();

struct flb_coro *flb_coro_get();
void flb_coro_set(struct flb_coro *coro);

static FLB_INLINE void flb_coro_resume(struct flb_coro *coro)
{
    flb_coro_set(coro);
    coro->caller = co_active();

    flb_coroutine_scheduler_set_coroutine_state(coro, 
                                                FLB_COROUTINE_STATUS_RUNNING);

    if (coro->time_slice != FLB_TIMESLICE_UNLIMITED) {
        coro->resume_time = flb_time_get_cpu_timestamp();
    }

    co_switch(coro->callee);
}

static FLB_INLINE struct flb_coro *flb_coro_create(void *data)
{
    struct flb_coro *coro;

    /* Create a thread context and initialize */
    coro = (struct flb_coro *) flb_calloc(1, sizeof(struct flb_coro));
    if (!coro) {
        flb_errno();
        return NULL;
    }
    coro->data = data;

    mk_list_entry_init(&coro->_head);

    flb_coroutine_scheduler_set_coroutine_state(coro, 
                                                FLB_COROUTINE_STATUS_PAUSED);

    return coro;
}

#ifdef __cplusplus
}
#endif

#endif /* !FLB_CORO_H */
