/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#ifndef FLB_THREAD_LIBCO_H
#define FLB_THREAD_LIBCO_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>

#include <monkey/mk_core.h>

#include <stdlib.h>
#include <limits.h>
#include <libco.h>

#ifdef FLB_HAVE_VALGRIND
#include <valgrind/valgrind.h>
#endif

struct flb_thread {

#ifdef FLB_HAVE_VALGRIND
    unsigned int valgrind_stack_id;
#endif

    /* libco 'contexts' */
    cothread_t caller;
    cothread_t callee;

    void *data;

    /*
     * Callback invoked before the thread is destroyed. Used to release
     * any pending info in FLB_THREAD_DATA(...).
     */
    void (*cb_destroy) (void *);
};

#ifdef FLB_CORO_STACK_SIZE
#define FLB_THREAD_STACK_SIZE      FLB_CORO_STACK_SIZE
#else
#define FLB_THREAD_STACK_SIZE      ((3 * PTHREAD_STACK_MIN) / 2)
#endif

#define FLB_THREAD_DATA(th)        (((char *) th) + sizeof(struct flb_thread))

FLB_EXPORT pthread_key_t flb_thread_key;

static FLB_INLINE void flb_thread_prepare()
{
    pthread_key_create(&flb_thread_key, NULL);
}

static FLB_INLINE void flb_thread_yield(struct flb_thread *th, int ended)
{
    co_switch(th->caller);
}

static FLB_INLINE void flb_thread_destroy(struct flb_thread *th)
{
    if (th->cb_destroy) {
        th->cb_destroy(FLB_THREAD_DATA(th));
    }
    flb_trace("[thread] destroy thread=%p data=%p", th, FLB_THREAD_DATA(th));

#ifdef FLB_HAVE_VALGRIND
    VALGRIND_STACK_DEREGISTER(th->valgrind_stack_id);
#endif

    co_delete(th->callee);
    flb_free(th);
}

#define flb_thread_return(th) co_switch(th->caller)

static FLB_INLINE void flb_thread_resume(struct flb_thread *th)
{
    pthread_setspecific(flb_thread_key, (void *) th);

    /*
     * In the past we used to have a flag to mark when a coroutine
     * has finished (th->ended == MK_TRUE), now we let the coroutine
     * to submit an event to the event loop indicating what's going on
     * through the call FLB_OUTPUT_RETURN(...).
     *
     * So we just swap context and let the event loop to handle all
     * the cleanup required.
     */

    th->caller = co_active();
    co_switch(th->callee);
}

static FLB_INLINE struct flb_thread *flb_thread_new(size_t data_size,
                                         void (*cb_destroy) (void *))

{
    void *p;
    struct flb_thread *th;

    /* Create a thread context and initialize */
    p = flb_malloc(sizeof(struct flb_thread) + data_size);
    if (!p) {
        flb_errno();
        return NULL;
    }

    th = (struct flb_thread *) p;
    th->cb_destroy = NULL;

    flb_trace("[thread %p] created (custom data at %p, size=%lu",
              th, FLB_THREAD_DATA(th), data_size);

    return th;
}

#endif
