/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#ifndef FLB_THREAD_UCONTEXT_H
#define FLB_THREAD_UCONTEXT_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>

#include <stdlib.h>
#include <limits.h>
#include <ucontext.h>

#ifdef FLB_HAVE_VALGRIND
#include <valgrind/valgrind.h>
#endif

struct flb_thread {

#ifdef FLB_HAVE_VALGRIND
    unsigned int valgrind_stack_id;
#endif

    /* ucontext 'contexts' */
    ucontext_t caller;
    ucontext_t callee;

    /*
     * Callback invoked before the thread is destroyed. Used to release
     * any pending info in FLB_THREAD_DATA(...).
     */
    void (*cb_destroy) (void *);
};

#define FLB_THREAD_STACK(th)     (((char *) th) + sizeof(struct flb_thread))
#define FLB_THREAD_STACK_SIZE    ((3 * PTHREAD_STACK_MIN) / 2)
#define FLB_THREAD_STACK_END(th) ((char *) FLB_THREAD_STACK(th) + FLB_THREAD_STACK_SIZE)
#define FLB_THREAD_DATA(th)      ((char *) FLB_THREAD_STACK_END(th))
#define FLB_THREAD_SIZE()        (sizeof(struct flb_thread) + FLB_THREAD_STACK_SIZE)

FLB_EXPORT pthread_key_t flb_thread_key;

static FLB_INLINE void flb_thread_prepare()
{
    pthread_key_create(&flb_thread_key, NULL);
}

static FLB_INLINE void flb_thread_yield(struct flb_thread *th, int ended)
{
    swapcontext(&th->callee, &th->caller);
}

static FLB_INLINE void flb_thread_destroy(struct flb_thread *th)
{
    if (th->cb_destroy) {
        th->cb_destroy(FLB_THREAD_DATA(th));
    }

    flb_trace("[thread] destroy thread=%p", th);

#ifdef FLB_HAVE_VALGRIND
    VALGRIND_STACK_DEREGISTER(th->valgrind_stack_id);
#endif

    flb_free(th);
}

#define flb_thread_return(th) flb_thread_yield(th, FLB_TRUE)

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
    swapcontext(&th->caller, &th->callee);
}

static struct flb_thread *flb_thread_new(size_t data_size,
                                         void (*cb_destroy) (void *))

{
    int ret;
    void *p;
    struct flb_thread *th;

    /* Create a thread context and initialize */
    p = flb_malloc(sizeof(struct flb_thread) + FLB_THREAD_STACK_SIZE + data_size);
    if (!p) {
        flb_errno();
        return NULL;
    }

    th = (struct flb_thread *) p;
    th->cb_destroy = NULL;

    ret = getcontext(&th->callee);
    if (ret == -1) {
        flb_errno();
        flb_free(th);
        return NULL;
    }

    /* Thread context */
    th->callee.uc_stack.ss_sp    = FLB_THREAD_STACK(p);
    th->callee.uc_stack.ss_size  = FLB_THREAD_STACK_SIZE;
    th->callee.uc_stack.ss_flags = 0;
    th->callee.uc_link           = &th->caller;

#ifdef FLB_HAVE_VALGRIND
    th->valgrind_stack_id = VALGRIND_STACK_REGISTER(FLB_THREAD_STACK(p),
                                                    FLB_THREAD_STACK(p) + FLB_THREAD_STACK_SIZE);
#endif

    flb_trace("[thread %p] created (custom data at %p, size=%lu",
              th, FLB_THREAD_DATA(th), data_size);
    return th;
}

#endif
