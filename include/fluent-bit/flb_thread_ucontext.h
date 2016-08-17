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

#ifdef FLB_HAVE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#include <ucontext.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_engine_task.h>

struct flb_thread {
    int id;
    int retries;

#ifdef FLB_HAVE_VALGRIND
    unsigned int valgrind_stack_id;
#endif

    /* ucontext 'contexts' */
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

    /* Parent flb_engine_task */
    struct flb_engine_task *task;

    struct flb_config *config;

    /* Link to struct flb_engine_task->threads */
    struct mk_list _head;
};

#define FLB_THREAD_STACK(p)    (((char *) p) + sizeof(struct flb_thread))
#define FLB_THREAD_STACK_SIZE  ((3 * PTHREAD_STACK_MIN) / 2)

FLB_EXPORT pthread_key_t flb_thread_key;

static FLB_INLINE struct flb_thread *flb_thread_get(int id,
                                                    struct flb_engine_task *task)
{
    struct mk_list *head;
    struct flb_thread *thread = NULL;

    mk_list_foreach(head, &task->threads) {
        thread = mk_list_entry(head, struct flb_thread, _head);
        if (thread->id == id) {
            return thread;
        }
    }

    return thread;
}

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
#ifdef FLB_HAVE_VALGRIND
    VALGRIND_STACK_DEREGISTER(th->valgrind_stack_id);
#endif

    flb_trace("[thread] destroy thread_id=%i", th->id);
    th->task->users--;
    mk_list_del(&th->_head);
    free(th);
}

static FLB_INLINE int flb_thread_destroy_id(int id, struct
                                            flb_engine_task *task)
{
    struct flb_thread *thread;

    thread = flb_thread_get(id, task);
    flb_thread_destroy(thread);

    return 0;
}

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
     * cleanup required.
     */
    swapcontext(&th->caller, &th->callee);
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

    th->id                       = 0;
    th->retries                  = 0;
    th->callee.uc_stack.ss_sp    = FLB_THREAD_STACK(p);
    th->callee.uc_stack.ss_size  = FLB_THREAD_STACK_SIZE;
    th->callee.uc_stack.ss_flags = 0;
    th->callee.uc_link           = &th->caller;

#ifdef FLB_HAVE_VALGRIND
    th->valgrind_stack_id = VALGRIND_STACK_REGISTER(FLB_THREAD_STACK(p),
                                                    FLB_THREAD_STACK(p) + FLB_THREAD_STACK_SIZE);
#endif

    flb_trace("[thread %p] created", th);

    return th;
}

#endif
