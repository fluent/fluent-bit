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
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_input.h>

/* Task status */
#define FLB_ENGINE_TASK_NEW      0
#define FLB_ENGINE_TASK_RUNNING  1

/* Task signals */
//#define FLB_ENGINE_TASK_DONE     FLB_ENGINE_MASK(FLB_ENGINE_TASK, 1)

struct flb_engine_task_route {
    struct flb_output_instance *out;
    struct mk_list _head;
};

/* A task takes a buffer and sync input and output instances to handle it */
struct flb_engine_task {
    int id;                                /* task id                   */
    int status;                            /* new task or running ?     */
    int deleted;                           /* should be deleted ?       */
    int users;                             /* number of users (threads) */
    char *tag;                             /* original tag              */
    char *buf;                             /* buffer                    */
    size_t size;                           /* buffer data size          */
    struct flb_input_dyntag *dt;           /* dyntag node (if applies)  */
    struct flb_input_instance *i_ins;      /* input instance            */
    struct mk_list threads;                /* ref flb_input_instance->tasks */
    struct mk_list routes;                 /* routes to dispatch data   */
    struct mk_list _head;                  /* link to input_instance    */
    struct flb_config *config;             /* parent flb config         */

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_t mutex_threads;
#endif
};

/* If there is no active users, mark the task as ready for destroy */
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
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_engine_task_route *route;

    if (task->dt) {
        flb_input_dyntag_destroy(task->dt);
    }

    /* Release task_id */
    task->config->tasks_map[task->id].id   = 0;
    task->config->tasks_map[task->id].task = NULL;

    /* Remove routes */
    mk_list_foreach_safe(head, tmp, &task->routes) {
        route = mk_list_entry(head, struct flb_engine_task_route, _head);
        mk_list_del(&route->_head);
        free(route);
    }

    /* Unlink and release */
    mk_list_del(&task->_head);
    free(task->buf);
    free(task->tag);
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

struct flb_engine_task *flb_engine_task_create(char *buf,
                                               size_t size,
                                               struct flb_input_instance *i_ins,
                                               struct flb_input_dyntag *dt,
                                               char *tag,
                                               struct flb_config *config);

#endif
