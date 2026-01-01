/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_TASK_H
#define FLB_TASK_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

/* Task status */
#define FLB_TASK_NEW      0
#define FLB_TASK_RUNNING  1

/*
 * Macro helpers to determinate return value, task_id and coro_id. When an
 * output plugin returns, it must call FLB_OUTPUT_RETURN(val) where val is
 * the return value, as of now defined as FLB_OK, FLB_ERROR or FLB_RETRY.
 *
 * The FLB_OUTPUT_RETURN macro lookup the current active 'engine coroutine' and
 * it 'engine task' associated, so it emits an event to the main event loop
 * indicating an output coroutine has finished. In order to specify return
 * values and the proper IDs an unsigned 32 bits number is used:
 *
 *     AAAA     BBBBBBBBBBBBBB CCCCCCCCCCCCCC   > 32 bit number
 *       ^            ^              ^
 *    4 bits       14 bits        14 bits
 *  return val     task_id       output_id
 */

#define FLB_TASK_RET(val)  (val >> 28)
#define FLB_TASK_ID(val)   (uint32_t) (val & 0xfffc000) >> 14
#define FLB_TASK_OUT(val)  (val & 0x3fff)
#define FLB_TASK_SET(ret, task_id, out_id)              \
    (uint32_t) ((ret << 28) | (task_id << 14) | out_id)

/* Route status */
#define FLB_TASK_ROUTE_INACTIVE 0
#define FLB_TASK_ROUTE_ACTIVE   1
#define FLB_TASK_ROUTE_DROPPED  2

struct flb_task_route {
    int status;
    struct flb_output_instance *out;
    struct mk_list _head;
};

/*
 * When a Task failed in an output instance plugin and this last one
 * requested a FLB_RETRY, a flb_engine_task_retry entry is created and
 * linked into the parent flb_engine_task->retries lists.
 *
 * This reference is used later by the scheduler to re-dispatch the
 * task data to the desired output path.
 */
struct flb_task_retry {
    int attempts;                       /* number of attempts, default 1 */
    struct flb_output_instance *o_ins;  /* route that we are retrying   */
    struct flb_task *parent;            /* parent task reference        */
    struct mk_list _head;               /* link to parent task list     */
};

/* A task takes a buffer and sync input and output instances to handle it */
struct flb_task {
    int id;                              /* task id                   */
    uint64_t ref_id;                     /* external reference id     */
    uint8_t status;                      /* new task or running ?     */
    int users;                           /* number of users (threads) */
    struct flb_event_chunk *event_chunk; /* event chunk context       */
    void *ic;                            /* input chunk context       */
#ifdef FLB_HAVE_METRICS
    int records;                         /* numbers of records in 'buf'   */
#endif
    struct mk_list routes;               /* routes to dispatch data       */
    struct mk_list retries;              /* queued in-memory retries      */
    struct mk_list _head;                /* link to input_instance        */
    struct flb_input_instance *i_ins;    /* input instance                */
    struct flb_config *config;           /* parent flb config             */
    pthread_mutex_t lock;
};

/*
 * A queue of flb_task_enqueued tasks
 *
 * This structure is currently used to track pending flushes when FLB_OUTPUT_SYNCHRONOUS
 * is used.
 */
struct flb_task_queue {
    struct mk_list pending;
    struct mk_list in_progress;
};

/*
 * An enqueued task is a task that is not yet dispatched to a thread
 * or started on the engine.
 *
 * There may be multiple enqueued instances of the same task on different out instances.
 *
 * This structure is currently used to track pending flushes when FLB_OUTPUT_SYNCHRONOUS
 * is used.
 */
struct flb_task_enqueued {
    struct flb_task *task;
    struct flb_task_retry *retry;
    struct flb_output_instance *out_instance;
    struct flb_config *config;
    struct mk_list _head;
};

int flb_task_running_count(struct flb_config *config);
int flb_task_running_print(struct flb_config *config);
int flb_task_map_get_task_id(struct flb_config *config);

struct flb_task *task_alloc(struct flb_config *config);

struct flb_task *flb_task_create(uint64_t ref_id,
                                 const char *buf,
                                 size_t size,
                                 struct flb_input_instance *i_ins,
                                 struct flb_input_chunk *ic,
                                 const char *tag_buf, int tag_len,
                                 struct flb_config *config,
                                 int *err);

void flb_task_add_coro(struct flb_task *task, struct flb_coro *coro);

void flb_task_destroy(struct flb_task *task, int del);

struct flb_task_queue* flb_task_queue_create();
void flb_task_queue_destroy(struct flb_task_queue *queue);
struct flb_task_retry *flb_task_retry_create(struct flb_task *task,
                                             struct flb_output_instance *ins);

void flb_task_retry_destroy(struct flb_task_retry *retry);
int flb_task_retry_reschedule(struct flb_task_retry *retry, struct flb_config *config);
int flb_task_from_fs_storage(struct flb_task *task);
int flb_task_retry_count(struct flb_task *task, void *data);
int flb_task_retry_clean(struct flb_task *task, struct flb_output_instance *ins);


struct flb_task *flb_task_chunk_create(uint64_t ref_id,
                                       const char *buf,
                                       size_t size,
                                       struct flb_input_instance *i_ins,
                                       void *ic,
                                       const char *tag_buf, int tag_len,
                                       struct flb_config *config);

static inline void flb_task_users_release(struct flb_task *task)
{
    if (task->users == 0 && mk_list_size(&task->retries) == 0) {
        flb_task_destroy(task, FLB_TRUE);
    }
}

/* Increase the counter for users */
static inline void flb_task_users_inc(struct flb_task *task)
{
    task->users++;
}

/*
 * Decrement the users counter from the task, and if release_check is enabled,
 * it will check if the task can be destroyed.
 */
static inline void flb_task_users_dec(struct flb_task *task, int release_check)
{
    task->users--;
    if (release_check == FLB_TRUE) {
        flb_task_users_release(task);
    }
}

static inline void flb_task_acquire_lock(struct flb_task *task)
{
    pthread_mutex_lock(&task->lock);
}

static inline void flb_task_release_lock(struct flb_task *task)
{
    pthread_mutex_unlock(&task->lock);
}

static FLB_INLINE int flb_task_get_active_route_count(
                        struct flb_task *task)
{
    struct mk_list        *iterator;
    int                    result;
    struct flb_task_route *route;

    result = 0;

    mk_list_foreach(iterator, &task->routes) {
        route = mk_list_entry(iterator, struct flb_task_route, _head);

        if (route->status == FLB_TASK_ROUTE_ACTIVE) {
            result++;
        }
    }

    return result;
}

static FLB_INLINE size_t flb_task_get_route_status(
                            struct flb_task *task,
                            struct flb_output_instance *o_ins)
{
    struct mk_list        *iterator;
    size_t                 result;
    struct flb_task_route *route;

    result = FLB_TASK_ROUTE_INACTIVE;

    mk_list_foreach(iterator, &task->routes) {
        route = mk_list_entry(iterator, struct flb_task_route, _head);

        if (route->out == o_ins) {
            result = route->status;
            break;
        }
    }

    return result;
}

static FLB_INLINE void flb_task_set_route_status(
                        struct flb_task *task,
                        struct flb_output_instance *o_ins,
                        int new_status)
{
    struct mk_list        *iterator;
    struct flb_task_route *route;

    mk_list_foreach(iterator, &task->routes) {
        route = mk_list_entry(iterator, struct flb_task_route, _head);

        if (route->out == o_ins) {
            route->status = new_status;
            break;
        }
    }
}


static FLB_INLINE void flb_task_activate_route(
                        struct flb_task *task,
                        struct flb_output_instance *o_ins)
{
    flb_task_set_route_status(task, o_ins, FLB_TASK_ROUTE_ACTIVE);
}

static FLB_INLINE void flb_task_deactivate_route(
                        struct flb_task *task,
                        struct flb_output_instance *o_ins)
{
    flb_task_set_route_status(task, o_ins, FLB_TASK_ROUTE_INACTIVE);
}

static FLB_INLINE void flb_task_drop_route(
                        struct flb_task *task,
                        struct flb_output_instance *o_ins)
{
    flb_task_set_route_status(task, o_ins, FLB_TASK_ROUTE_DROPPED);
}

#endif
