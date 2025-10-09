/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <stdio.h>
#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_scheduler.h>

/*
 * Every task created must have an unique ID, this function lookup the
 * lowest number available in the task_map.
 *
 * This 'id' is used by the task interface to communicate with the engine event
 * loop about some action.
 */

static inline int map_get_task_id(struct flb_config *config)
{
    int result;
    int i;

    for (i = 0; i < config->task_map_size ; i++) {
        if (config->task_map[i].task == NULL) {
            return i;
        }
    }

    result = flb_config_task_map_grow(config);

    if (result == 0) {
        return i;
    }

    return -1;
}

static inline void map_set_task_id(int id, struct flb_task *task,
                                   struct flb_config *config)
{
    config->task_map[id].task = task;

}

static inline void map_free_task_id(int id, struct flb_config *config)
{
    config->task_map[id].task = NULL;
}

void flb_task_retry_destroy(struct flb_task_retry *retry)
{
    int ret;

    /* Make sure to invalidate any request from the scheduler */
    ret = flb_sched_request_invalidate(retry->parent->config, retry);
    if (ret == 0) {
        flb_debug("[retry] task retry=%p, invalidated from the scheduler",
                  retry);
    }

    mk_list_del(&retry->_head);
    flb_free(retry);
}

/*
 * For an existing task 'retry', re-schedule it. One of the use case of this function
 * is when the engine dispatcher fails to bring the chunk up due to Chunk I/O
 * configuration restrictions, the task needs to be re-scheduled.
 */
int flb_task_retry_reschedule(struct flb_task_retry *retry, struct flb_config *config)
{
    int seconds;
    struct flb_task *task;

    task = retry->parent;
    seconds = flb_sched_request_create(config, retry, retry->attempts);
    if (seconds == -1) {
        /*
         * This is the worse case scenario: 'cannot re-schedule a retry'. If the Chunk
         * resides only in memory, it will be lost.  */
        flb_warn("[task] retry for task %i could not be re-scheduled", task->id);
        flb_task_retry_destroy(retry);
        if (task->users == 0 && mk_list_size(&task->retries) == 0) {
            flb_task_destroy(task, FLB_TRUE);
        }
        return -1;
    }
    else {
        flb_info("[task] re-schedule retry=%p %i in the next %i seconds",
                  retry, task->id, seconds);
    }

    return 0;
}

struct flb_task_retry *flb_task_retry_create(struct flb_task *task,
                                             struct flb_output_instance *ins)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_task_retry *retry = NULL;

    /* First discover if is there any previous retry context in the task */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);
        if (retry->o_ins == ins) {
            if (retry->attempts >= ins->retry_limit && ins->retry_limit >= 0) {
                flb_debug("[task] task_id=%i reached retry-attempts limit %i/%i",
                          task->id, retry->attempts, ins->retry_limit);
                flb_task_retry_destroy(retry);
                return NULL;
            }
            break;
        }
        retry = NULL;
    }

    if (!retry) {
        /* Create a new re-try instance */
        retry = flb_malloc(sizeof(struct flb_task_retry));
        if (!retry) {
            flb_errno();
            return NULL;
        }

        retry->attempts = 1;
        retry->o_ins   = ins;
        retry->parent  = task;
        mk_list_add(&retry->_head, &task->retries);

        flb_debug("[retry] new retry created for task_id=%i attempts=%i",
                  task->id, retry->attempts);
    }
    else {
        retry->attempts++;
        flb_debug("[retry] re-using retry for task_id=%i attempts=%i",
                  task->id, retry->attempts);
    }

    /*
     * This 'retry' was issued by an output plugin, from an Engine perspective
     * we need to determinate if the source input plugin have some memory
     * restrictions and if the Storage type is 'filesystem' we need to put
     * the file content down.
     *
     * Note that we can only put the chunk down if there are no more active users
     * otherwise it can lead to a corruption (https://github.com/fluent/fluent-bit/issues/8691)
     */

    if (task->users <= 1) {
        flb_input_chunk_set_up_down(task->ic);
    }

    /*
     * Besides limits adjusted above, a retry that's going to only one place
     * must be down.
     */
    if (mk_list_size(&task->routes) == 1) {
        flb_input_chunk_down(task->ic);
    }

    return retry;
}

/*
 * Return FLB_TRUE or FLB_FALSE if the chunk pointed by the task was
 * created on this running instance or it comes from a chunk in the
 * filesystem from a previous run.
 */
int flb_task_from_fs_storage(struct flb_task *task)
{
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) task->ic;
    return ic->fs_backlog;
}

int flb_task_retry_count(struct flb_task *task, void *data)
{
    struct mk_list *head;
    struct flb_task_retry *retry;
    struct flb_output_instance *o_ins;

    o_ins = (struct flb_output_instance *) data;

    mk_list_foreach(head, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);

        if (retry->o_ins == o_ins) {
            return retry->attempts;
        }
    }

    return -1;
}

/* Check if a 'retry' context exists for a specific task, if so, cleanup */
int flb_task_retry_clean(struct flb_task *task, struct flb_output_instance *ins)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_task_retry *retry;

    /* Delete 'retries' only associated with the output instance */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);
        if (retry->o_ins == ins) {
            flb_task_retry_destroy(retry);
            return 0;
        }
    }

    return -1;
}

/* Allocate an initialize a basic Task structure */
struct flb_task *task_alloc(struct flb_config *config)
{
    int task_id;
    struct flb_task *task;

    /* Allocate the new task */
    task = (struct flb_task *) flb_calloc(1, sizeof(struct flb_task));
    if (!task) {
        flb_errno();
        return NULL;
    }

    /* Get ID and set back 'task' reference */
    task_id = map_get_task_id(config);
    if (task_id == -1) {
        flb_free(task);
        return NULL;
    }

    map_set_task_id(task_id, task, config);

    flb_trace("[task %p] created (id=%i)", task, task_id);

    /* Initialize minimum variables */
    task->id        = task_id;
    task->config    = config;
    task->status    = FLB_TASK_NEW;
    task->users     = 0;
    mk_list_init(&task->routes);
    mk_list_init(&task->retries);

    pthread_mutex_init(&task->lock, NULL);

    return task;
}

/* Return the number of tasks with 'running status' or tasks with retries */
int flb_task_running_count(struct flb_config *config)
{
    int count = 0;
    struct mk_list *head;
    struct mk_list *t_head;
    struct flb_task *task;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        mk_list_foreach(t_head, &ins->tasks) {
            task = mk_list_entry(t_head, struct flb_task, _head);
            if (task->users > 0 || mk_list_size(&task->retries) > 0) {
                count++;
            }
        }
    }

    return count;
}

int flb_task_running_print(struct flb_config *config)
{
    int count = 0;
    flb_sds_t tmp;
    flb_sds_t routes;
    struct mk_list *head;
    struct mk_list *t_head;
    struct mk_list *r_head;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_input_instance *ins;

    routes = flb_sds_create_size(256);
    if (!routes) {
        flb_error("[task] cannot allocate space to report pending tasks");
        return -1;
    }

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        count = mk_list_size(&ins->tasks);
        flb_info("[task] %s/%s has %i pending task(s):",
                 ins->p->name, flb_input_name(ins), count);
        mk_list_foreach(t_head, &ins->tasks) {
            task = mk_list_entry(t_head, struct flb_task, _head);

            mk_list_foreach(r_head, &task->routes) {
                route = mk_list_entry(r_head, struct flb_task_route, _head);
                tmp = flb_sds_printf(&routes, "%s/%s ",
                                     route->out->p->name,
                                     flb_output_name(route->out));
                if (!tmp) {
                    flb_sds_destroy(routes);
                    flb_error("[task] cannot print report for pending tasks");
                    return -1;
                }
                routes = tmp;
            }

            flb_info("[task]   task_id=%i still running on route(s): %s",
                     task->id, routes);
            flb_sds_len_set(routes, 0);
        }
    }
    flb_sds_destroy(routes);
    return 0;
}

int flb_task_map_get_task_id(struct flb_config *config) {
    return map_get_task_id(config);
}

/* Create an engine task to handle the output plugin flushing work */
struct flb_task *flb_task_create(uint64_t ref_id,
                                 const char *buf,
                                 size_t size,
                                 struct flb_input_instance *i_ins,
                                 struct flb_input_chunk *ic,
                                 const char *tag_buf, int tag_len,
                                 struct flb_config *config,
                                 int *err)
{
    int count = 0;
    int total_events = 0;
    struct flb_task *task;
    struct flb_event_chunk *evc;
    struct flb_task_route *route;
    struct flb_router_path *route_path;
    struct flb_output_instance *o_ins;
    struct flb_input_chunk *task_ic;
    struct mk_list *i_head;
    struct mk_list *o_head;

    /* No error status */
    *err = FLB_FALSE;

    /* allocate task */
    task = task_alloc(config);
    if (!task) {
        *err = FLB_TRUE;
        return NULL;
    }

    total_events = ((struct flb_input_chunk *) ic)->total_records;

    /* event chunk */
    evc = flb_event_chunk_create(ic->event_type,
                                 total_events,
                                 (char *) tag_buf, tag_len,
                                 (char *) buf, size);
    if (!evc) {
        flb_free(task);
        *err = FLB_TRUE;
        return NULL;
    }

#ifdef FLB_HAVE_CHUNK_TRACE
    if (ic->trace) {
        flb_debug("add trace to task");
        evc->trace = ic->trace;
    }
#endif

    task->event_chunk = evc;
    task_ic = (struct flb_input_chunk *) ic;
    task_ic->task = task;

    /* Keep track of origins */
    task->ref_id = ref_id;
    task->i_ins  = i_ins;
    task->ic     = ic;
    mk_list_add(&task->_head, &i_ins->tasks);

#ifdef FLB_HAVE_METRICS
    task->records = ((struct flb_input_chunk *) ic)->total_records;
#endif

    /* Direct connects betweek input <> outputs (API based) */
    if (mk_list_size(&i_ins->routes_direct) > 0) {
        mk_list_foreach(i_head, &i_ins->routes_direct) {
            route_path = mk_list_entry(i_head, struct flb_router_path, _head);
            o_ins = route_path->ins;

            route = flb_malloc(sizeof(struct flb_task_route));
            if (!route) {
                flb_errno();
                task->event_chunk->data = NULL;
                flb_task_destroy(task, FLB_TRUE);
                return NULL;
            }

            route->out = o_ins;
            mk_list_add(&route->_head, &task->routes);
        }
        flb_debug("[task] created direct task=%p id=%i OK", task, task->id);
        return task;
    }

    /* Find matching routes for the incoming task */
    mk_list_foreach(o_head, &config->outputs) {
        o_ins = mk_list_entry(o_head,
                              struct flb_output_instance, _head);

        /* skip output plugins that don't handle proper event types */
        if (!flb_router_match_type(ic->event_type, o_ins)) {
            continue;
        }

        if (flb_routes_mask_get_bit(task_ic->routes_mask,
                                    o_ins->id,
                                    o_ins->config->router) != 0) {
            route = flb_calloc(1, sizeof(struct flb_task_route));
            if (!route) {
                flb_errno();
                continue;
            }

            route->status = FLB_TASK_ROUTE_INACTIVE;
            route->out = o_ins;
            mk_list_add(&route->_head, &task->routes);
            count++;
        }
    }

    /* no destinations ?, useless task. */
    if (count == 0) {
        flb_debug("[task] created task=%p id=%i without routes, dropping.",
                  task, task->id);
        task->event_chunk->data = NULL;
        flb_task_destroy(task, FLB_TRUE);
        return NULL;
    }

    flb_debug("[task] created task=%p id=%i OK", task, task->id);
    return task;
}

void flb_task_destroy(struct flb_task *task, int del)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_task_route *route;
    struct flb_task_retry *retry;

    flb_debug("[task] destroy task=%p (task_id=%i)", task, task->id);

    /* Release task_id */
    map_free_task_id(task->id, task->config);

    /* Remove routes */
    mk_list_foreach_safe(head, tmp, &task->routes) {
        route = mk_list_entry(head, struct flb_task_route, _head);
        mk_list_del(&route->_head);
        flb_free(route);
    }

    /* Unlink and release task */
    if (!mk_list_entry_is_orphan(&task->_head)) {
        mk_list_del(&task->_head);
    }

    /* destroy chunk */
    if (task->ic != NULL) {
        flb_input_chunk_destroy(task->ic, del);
    }

    /* Remove 'retries' */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);

        flb_task_retry_destroy(retry);
    }

    if (task->i_ins != NULL) {
        flb_input_chunk_set_limits(task->i_ins);
    }

    if (task->event_chunk != NULL) {
        flb_event_chunk_destroy(task->event_chunk);
    }

    flb_free(task);
}

struct flb_task_queue* flb_task_queue_create() {
    struct flb_task_queue *tq;
    tq = flb_malloc(sizeof(struct flb_task_queue));
    if (!tq) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&tq->pending);
    mk_list_init(&tq->in_progress);
    return tq;
}

void flb_task_queue_destroy(struct flb_task_queue *queue) {
    struct flb_task_enqueued *queued_task;
    struct mk_list *tmp;
    struct mk_list *head;

    mk_list_foreach_safe(head, tmp, &queue->pending) {
        queued_task = mk_list_entry(head, struct flb_task_enqueued, _head);
        mk_list_del(&queued_task->_head);
        flb_free(queued_task);
    }

    mk_list_foreach_safe(head, tmp, &queue->in_progress) {
        queued_task = mk_list_entry(head, struct flb_task_enqueued, _head);
        mk_list_del(&queued_task->_head);
        flb_free(queued_task);
    }

    flb_free(queue);
}
