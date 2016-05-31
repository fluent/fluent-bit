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

#ifndef FLB_THREAD_PTHREADS_H
#define FLB_THREAD_PTHREADS_H

#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_engine_task.h>

struct flb_input_instance;
struct flb_output_instance;

struct flb_thread {
    int ended;
#ifdef FLB_HAVE_VALGRIND
    unsigned int valgrind_stack_id;
#endif

    /* Thread ID */
    pthread_t tid;

    /* Thread callback info */
    struct flb_thread_pcb {
        void *buf;
        size_t size;
        char *tag;
        int tag_len;
        struct flb_input_instance *i_ins;
        struct flb_output_instance *o_ins;
    } pth_cb;

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

static FLB_INLINE void flb_thread_prepare()
{
}

static struct flb_thread *flb_thread_new()
{
    struct flb_thread *th;

    th = (struct flb_thread *) malloc(sizeof(struct flb_thread));
    if (!th) {
        perror("malloc");
        return NULL;
    }

    return th;
}

void flb_thread_resume(struct flb_thread *th);

static FLB_INLINE void flb_thread_yield(struct flb_thread *th, int ended)
{
}

static FLB_INLINE void flb_thread_destroy(struct flb_thread *th)
{
#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_lock(&th->task->mutex_threads);
#endif

    mk_list_del(&th->_head);

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_unlock(&th->task->mutex_threads);
#endif

    free(th);
}

void flb_thread_resume(struct flb_thread *th);

#endif
