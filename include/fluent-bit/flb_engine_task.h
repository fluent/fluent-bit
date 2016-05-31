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

#ifndef FLB_ENGINE_TASK_H
#define FLB_ENGINE_TASK_H

struct flb_thread;

#include <pthread.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_input.h>

/* A task takes a buffer and sync input and output instances to handle it */
struct flb_engine_task {
    int deleted;                           /* should be deleted ?       */
    int users;                             /* number of users (threads) */
    char *buf;                             /* buffer                    */
    size_t size;                           /* buffer data size          */
    struct flb_input_dyntag *dt;           /* dyntag node (if applies)  */
    struct flb_input_instance *i_ins;      /* input instance            */
    struct mk_list threads;                /* ref flb_input_instance->tasks */
    struct mk_list _head;

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_t mutex_threads;
#endif
};

/* Create an engine task to handle the output plugin flushing work */
static inline
struct flb_engine_task *flb_engine_task_create(char *buf,
                                               size_t size,
                                               struct flb_input_instance *i_ins,
                                               struct flb_input_dyntag *dt)
{
    struct flb_engine_task *task;

    task = (struct flb_engine_task *) calloc(1, sizeof(struct flb_engine_task));
    if (!task) {
        perror("malloc");
        return NULL;
    }

    /* Keep track of origins */
    task->deleted = FLB_FALSE;
    task->users   = 0;
    task->buf     = buf;
    task->size    = size;
    task->i_ins   = i_ins;
    task->dt      = dt;
    mk_list_init(&task->threads);
    mk_list_add(&task->_head, &i_ins->tasks);

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_init(&task->mutex_threads, NULL);
#endif

    return task;
}

/* If there is no active users, destroy the task context */
static inline int flb_engine_task_remove(struct flb_engine_task *task)
{
    /* Handle task users */
    task->users--;
    if (task->users == 0) {
        task->deleted = FLB_TRUE;
    }

    return 1;
}

static inline void flb_engine_task_destroy(struct flb_engine_task *task)
{
    if (task->dt) {
        flb_input_dyntag_destroy(task->dt);
    }

    mk_list_del(&task->_head);

    free(task->buf);
    free(task);
}

/* Register a thread into the tasks list */
static inline void flb_engine_task_add_thread(struct mk_list *head,
                                              struct flb_engine_task *task)
{
    /*
     * It's likely a previous thread have marked this task ready to be deleted,
     * we must check this usual condition that could happen when one input
     * instance must flush the data to many destinations.
     */
#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_lock(&task->mutex_threads);
#endif

    if (task->deleted == FLB_TRUE) {
        task->deleted = FLB_FALSE;
    }

    mk_list_add(head, &task->threads);
    task->users++;

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_unlock(&task->mutex_threads);
#endif
}

#endif
