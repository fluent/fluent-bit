/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2016 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_THREAD_UCONTEXT_H
#define MK_THREAD_UCONTEXT_H

#include <ucontext.h>
#include <pthread.h>
#include <limits.h>
#include <valgrind/valgrind.h>

#include <monkey/mk_core.h>
#include <monkey/mk_tls.h>

struct mk_thread {
    int id;

    unsigned int valgrind_stack_id;

    /* ucontext 'contexts' */
    ucontext_t caller;
    ucontext_t callee;

    /*
     * Callback invoked before the thread is destroyed. Used to release
     * any pending info in MK_THREAD_DATA(...).
     */
    void (*cb_destroy) (void *);
};

#define MK_THREAD_STACK(th)     (((char *) th) + sizeof(struct mk_thread))
#define MK_THREAD_STACK_SIZE    ((3 * PTHREAD_STACK_MIN) / 2)
#define MK_THREAD_STACK_END(th) ((char *) MK_THREAD_STACK(th) + MK_THREAD_STACK_SIZE)
#define MK_THREAD_DATA(th)      ((char *) MK_THREAD_STACK_END(th))
#define MK_THREAD_SIZE()        (sizeof(struct mk_thread) + MK_THREAD_STACK_SIZE)

extern MK_EXPORT MK_TLS_DEFINE(struct mk_thread, mk_thread);

static MK_INLINE void *mk_thread_get()
{
    return MK_TLS_GET(mk_thread);
}

static MK_INLINE void mk_thread_yield(struct mk_thread *th, int ended)
{
    (void) ended;

    swapcontext(&th->callee, &th->caller);
}

static MK_INLINE void mk_thread_destroy(struct mk_thread *th)
{
    if (th->cb_destroy) {
        th->cb_destroy(MK_THREAD_DATA(th));
    }

    VALGRIND_STACK_DEREGISTER(th->valgrind_stack_id);

    free(th);
}

static MK_INLINE void mk_thread_resume(struct mk_thread *th)
{
    MK_TLS_SET(mk_thread, th);

    /*
     * In the past we used to have a flag to mark when a coroutine
     * has finished (th->ended == MK_TRUE), now we let the coroutine
     * to submit an event to the event loop indicating what's going on
     * through the call MK_OUTPUT_RETURN(...).
     *
     * So we just swap context and let the event loop to handle all
     * the cleanup required.
     */
    swapcontext(&th->caller, &th->callee);
}

static inline struct mk_thread *mk_thread_new(size_t data_size,
                                       void (*cb_destroy) (void *))

{
    int ret;
    void *p;
    struct mk_thread *th;

    /* Create a thread context and initialize */
    p = malloc(sizeof(struct mk_thread) + MK_THREAD_STACK_SIZE + data_size);
    if (!p) {
        return NULL;
    }

    th = (struct mk_thread *) p;
    th->cb_destroy = cb_destroy;

    ret = getcontext(&th->callee);
    if (ret == -1) {
        free(th);
        return NULL;
    }

    /* Thread context */
    th->callee.uc_stack.ss_sp    = MK_THREAD_STACK(p);
    th->callee.uc_stack.ss_size  = MK_THREAD_STACK_SIZE;
    th->callee.uc_stack.ss_flags = 0;
    th->callee.uc_link           = &th->caller;

    th->valgrind_stack_id = VALGRIND_STACK_REGISTER(MK_THREAD_STACK(p),
                                                    MK_THREAD_STACK(p) + MK_THREAD_STACK_SIZE);

    return th;
}

#endif
