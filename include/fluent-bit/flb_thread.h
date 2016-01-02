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

#ifndef FLB_THREAD_H
#define FLB_THREAD_H

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#include <ucontext.h>

#include <limits.h>
#include <inttypes.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>

pthread_key_t flb_thread_key;

struct flb_thread {
    int ended;
#ifdef USE_VALGRIND
    unsigned int valgrind_stack_id;
#endif
    ucontext_t caller;
    ucontext_t callee;


    /*
     * Reference to some internal data, for output plugins it usually
     * reference the associated plugin in question where this thread
     * should help.
     */
    void *data;

    /*
     * Link to the buffer data originally passed for flushing, when the thread
     * exits this reference must be freed.
     */
    void *output_buffer;
};

#define FLB_THREAD_STACK(p)    (((char *) p) + sizeof(struct flb_thread))
#define FLB_THREAD_STACK_SIZE  ((3 * PTHREAD_STACK_MIN) / 2)

static FLB_INLINE void flb_thread_yield(struct flb_thread *th, int ended)
{
    th->ended = ended;
    swapcontext(&th->callee, &th->caller);
}

static FLB_INLINE void flb_thread_destroy(struct flb_thread *th)
{
#ifdef USE_VALGRIND
    VALGRIND_STACK_DEREGISTER(th->valgrind_stack_id);
#endif
    if (th->output_buffer) {
        free(th->output_buffer);
    }
    free(th);
}

static FLB_INLINE void flb_thread_resume(struct flb_thread *th)
{
    /*
     * Always assume the coroutine will end, the callee can change
     * this behavior when yielding.
     */
    th->ended = MK_TRUE;
    swapcontext(&th->caller, &th->callee);

    /* It ended, destroy the thread (coroutine) */
    if (th->ended == MK_TRUE) {
        flb_debug("[thread %p] ended", th);
        flb_thread_destroy(th);
    }
}

static struct flb_thread *flb_thread_new()
{
    int ret;
    void *p;
    struct flb_thread *th;

    /* Create a thread context and initialize */
    p = malloc(sizeof(struct flb_thread) + FLB_THREAD_STACK_SIZE);
    if (!p) {
        perror("malloc");
        return NULL;
    }

    th = (struct flb_thread *) p;
    ret = getcontext(&th->callee);
    if (ret == -1) {
        perror("getcontext");
        free(th);
        return NULL;
    }

    th->callee.uc_stack.ss_sp    = FLB_THREAD_STACK(p);
    th->callee.uc_stack.ss_size  = FLB_THREAD_STACK_SIZE;
    th->callee.uc_stack.ss_flags = 0;
    th->callee.uc_link           = &th->caller;
    th->ended                    = MK_TRUE;

#ifdef USE_VALGRIND
    th->valgrind_stack_id = VALGRIND_STACK_REGISTER(FLB_THREAD_STACK(p),
                                                    FLB_THREAD_STACK(p) + FLB_THREAD_STACK_SIZE);
#endif

    flb_debug("[thread %p] created", th);

    return th;
}

#endif
