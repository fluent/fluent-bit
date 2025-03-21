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

#ifndef MK_THREAD_LIBCO_H
#define MK_THREAD_LIBCO_H

#include <monkey/mk_info.h>
#include <monkey/mk_core.h>
#include <libco.h>

#include <limits.h>

#ifdef MK_HAVE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#include <monkey/mk_tls.h>

struct mk_thread {

#ifdef MK_HAVE_VALGRIND
    unsigned int valgrind_stack_id;
#endif

    /* libco 'contexts' */
    cothread_t caller;
    cothread_t callee;

    void *data;

    /*
     * Callback invoked before the thread is destroyed. Used to release
     * any pending info in MK_THREAD_DATA(...).
     */
    void (*cb_destroy) (void *);
};

#define MK_THREAD_STACK_SIZE      ((3 * PTHREAD_STACK_MIN) / 2)
#define MK_THREAD_DATA(th)        (((char *) th) + sizeof(struct mk_thread))

extern MK_EXPORT MK_TLS_DEFINE(struct mk_thread, mk_thread);

static MK_INLINE void mk_thread_yield(struct mk_thread *th)
{
    co_switch(th->caller);
}

static MK_INLINE void mk_thread_destroy(struct mk_thread *th)
{
    if (th->cb_destroy) {
        th->cb_destroy(MK_THREAD_DATA(th));
    }

    MK_TRACE("[thread] destroy thread=%p data=%p", th, MK_THREAD_DATA(th));

#ifdef MK_HAVE_VALGRIND
    VALGRIND_STACK_DEREGISTER(th->valgrind_stack_id);
#endif

    co_delete(th->callee);
    mk_mem_free(th);
}

#define mk_thread_return(th) co_switch(th->caller)

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

    th->caller = co_active();
    co_switch(th->callee);
}

static MK_INLINE struct mk_thread *mk_thread_new(size_t data_size,
                                                 void (*cb_destroy) (void *))

{
    void *p;
    struct mk_thread *th;

    /* Create a thread context and initialize */
    p = mk_mem_alloc(sizeof(struct mk_thread) + data_size);
    if (!p) {

        return NULL;
    }

    th = (struct mk_thread *) p;
    th->cb_destroy = cb_destroy;

    MK_TRACE("[thread %p] created (custom data at %p, size=%lu",
              th, MK_THREAD_DATA(th), data_size);

    return th;
}

#endif
