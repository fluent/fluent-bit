/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_scheduler.h>

#ifdef FLB_HAVE_BUFFERING
#include <fluent-bit/flb_sha1.h>
#include <fluent-bit/flb_buffer_chunk.h>
#include <fluent-bit/flb_buffer_qchunk.h>
#endif

/*
 * Every task created must have an unique ID, this function lookup the
 * lowest number available in the tasks_map.
 *
 * This 'id' is used by the task interface to communicate with the engine event
 * loop about some action.
 */

static inline int map_get_task_id(struct flb_config *config)
{
    int i;
    int map_size = (sizeof(config->tasks_map) / sizeof(struct flb_task_map));

    for (i = 0; i < map_size; i++) {
        if (config->tasks_map[i].task == NULL) {
            return i;
        }
    }

    return -1;
}

static inline void map_set_task_id(int id, struct flb_task *task,
                                   struct flb_config *config)
{
    config->tasks_map[id].task = task;

}

static inline void map_free_task_id(int id, struct flb_config *config)
{
    config->tasks_map[id].task = NULL;
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

struct flb_task_retry *flb_task_retry_create(struct flb_task *task,
                                             void *data)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_task_retry *retry = NULL;
    struct flb_output_instance *o_ins;
    struct flb_output_thread *out_th;

    out_th = (struct flb_output_thread *) data;
    o_ins = out_th->o_ins;

    /* First discover if is there any previous retry context in the task */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);
        if (retry->o_ins == o_ins) {
            if (retry->attemps > o_ins->retry_limit && o_ins->retry_limit >= 0) {
                flb_debug("[task] task_id=%i reached retry-attemps limit %i/%i",
                          task->id, retry->attemps, o_ins->retry_limit);
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
            perror("malloc");
            return NULL;
        }

        retry->attemps = 1;
        retry->o_ins   = o_ins;
        retry->parent  = task;
        mk_list_add(&retry->_head, &task->retries);

        flb_debug("[retry] new retry created for task_id=%i attemps=%i",
                  out_th->task->id, retry->attemps);
    }
    else {
        retry->attemps++;
        flb_debug("[retry] re-using retry for task_id=%i attemps=%i",
                  out_th->task->id, retry->attemps);
    }

    return retry;
}

/* Check if a 'retry' context exists for a specific task, if so, cleanup */
int flb_task_retry_clean(struct flb_task *task, void *data)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_task_retry *retry;
    struct flb_output_instance *o_ins;
    struct flb_output_thread *out_th;

    out_th = (struct flb_output_thread *) FLB_THREAD_DATA(data);
    o_ins = out_th->o_ins;

    /* Delete 'retries' only associated with the output instance */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);
        if (retry->o_ins == o_ins) {
            flb_task_retry_destroy(retry);
            return 0;
        }
    }

    return -1;
}

/* Allocate an initialize a basic Task structure */
static struct flb_task *task_alloc(struct flb_config *config)
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
    task->mapped    = FLB_FALSE;
    task->config    = config;
    task->status    = FLB_TASK_NEW;
    task->n_threads = 0;
    task->users     = 0;
    mk_list_init(&task->threads);
    mk_list_init(&task->routes);
    mk_list_init(&task->retries);

    return task;
}

/* Create an engine task to handle the output plugin flushing work */
struct flb_task *flb_task_create(uint64_t ref_id,
                                 char *buf,
                                 size_t size,
                                 struct flb_input_instance *i_ins,
                                 struct flb_input_dyntag *dt,
                                 char *tag,
                                 struct flb_config *config)
{
    int count = 0;
    uint64_t routes_mask = 0;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_output_instance *o_ins;
    struct flb_router_path *router_path;
    struct mk_list *head;
    struct mk_list *o_head;

    task = task_alloc(config);
    if (!task) {
        return NULL;
    }

    /* Keep track of origins */
    task->ref_id = ref_id;
    task->tag    = flb_strdup(tag);
    task->buf    = buf;
    task->size   = size;
    task->i_ins  = i_ins;
    task->dt     = dt;
    task->destinations = 0;
    mk_list_add(&task->_head, &i_ins->tasks);

    /* Routes */
    if (!dt) {
        /* A non-dynamic tag input plugin have static routes */
        mk_list_foreach(head, &i_ins->routes) {
            router_path = mk_list_entry(head, struct flb_router_path, _head);
            o_ins = router_path->ins;

            route = flb_malloc(sizeof(struct flb_task_route));
            if (!route) {
                flb_errno();
                continue;
            }

            route->out = o_ins;
            mk_list_add(&route->_head, &task->routes);
            count++;

            routes_mask |= o_ins->mask_id;
        }
    }
    else {
        /* Find dynamic routes for the incoming tag */
        mk_list_foreach(o_head, &config->outputs) {
            o_ins = mk_list_entry(o_head,
                                  struct flb_output_instance, _head);
            if (!o_ins->match) {
                continue;
            }

            if (flb_router_match(tag, o_ins->match
#ifdef FLB_HAVE_REGEX
                , o_ins->match_regex
#endif
            )) {
                route = flb_malloc(sizeof(struct flb_task_route));
                if (!route) {
                    flb_errno();
                    continue;
                }

                route->out = o_ins;
                mk_list_add(&route->_head, &task->routes);
                count++;

                /* set the routes as a mask */
                routes_mask |= o_ins->mask_id;
            }
        }
    }

    /* no destinations ?, useless task. */
    if (count == 0) {
        flb_debug("[task] created task=%p id=%i without routes, dropping.",
                  task, task->id);
        task->buf = NULL;
        flb_task_destroy(task);
        return NULL;
    }

#ifdef FLB_HAVE_BUFFERING
    int i;
    int worker_id;

    /* If no buffering is set, return right away */
    if (!config->buffer_ctx) {
        flb_debug("[task] created task=%p id=%i OK", task, task->id);
        return task;
    }

    /* Generate content SHA1 and it Hexa representation */
    flb_sha1_encode(buf, size, task->hash_sha1);
    for (i = 0; i < 20; ++i) {
        sprintf(&task->hash_hex[i*2], "%02x", task->hash_sha1[i]);
    }
    task->hash_hex[40] = '\0';

    /*
     * Generate a buffer chunk push request, note that suggested routes
     * are passed through the 'routes_mask' bit mask variable.
     */
    worker_id = flb_buffer_chunk_push(config->buffer_ctx, buf, size, tag,
                                      routes_mask, task->hash_hex);

    task->worker_id = worker_id;
    flb_debug("[task->buffer] worker_id=%i", worker_id);
#endif

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_init(&task->mutex_threads, NULL);
#endif

    flb_debug("[task] created task=%p id=%i OK", task, task->id);
    return task;
}

/*
 * Create an engine task to handle the output plugin flushing work. Not that
 * doing a direct Task will not do buffering.
 */
struct flb_task *flb_task_create_direct(uint64_t ref_id,
                                        char *buf,
                                        size_t size,
                                        struct flb_input_instance *i_ins,
                                        char *tag,
                                        char *hash,
                                        uint64_t routes,
                                        struct flb_config *config)
{
    int count = 0;
    struct mk_list *head;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_output_instance *o_ins;

    /* Allocate a task structure */
    task = task_alloc(config);
    if (!task) {
        return NULL;
    }

    /* Keep track of origins */
    task->ref_id    = ref_id;
    task->tag       = flb_strdup(tag);
    task->buf       = buf;
    task->size      = size;
    task->i_ins     = i_ins;
    task->dt        = NULL;
    task->mapped    = FLB_TRUE;
#ifdef FLB_HAVE_BUFFERING
    memcpy(&task->hash_hex, hash, 41);
#endif
    mk_list_add(&task->_head, &i_ins->tasks);

    /* Iterate output instances and try to match the routes */
    mk_list_foreach(head, &config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (o_ins->mask_id & routes) {
            route = flb_malloc(sizeof(struct flb_task_route));
            if (!route) {
                perror("malloc");
                continue;
            }

            route->out = o_ins;
            mk_list_add(&route->_head, &task->routes);
            count++;
        }
    }

    flb_debug("[task] create_direct: %i routes", count);

    return task;
}

void flb_task_destroy(struct flb_task *task)
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

    /* Unlink and release */
    mk_list_del(&task->_head);

    if (task->mapped == FLB_FALSE) {
        if (task->dt && task->buf) {
            if (task->buf != task->dt->mp_sbuf.data) {
                flb_free(task->buf);
            }
        }
        else {
            flb_free(task->buf);
        }
    }
#ifdef FLB_HAVE_BUFFERING
    else {
        /* Likely there is a qchunk associated to this tasks */
        if (task->ref_id > 0 && task->config->buffer_ctx) {
            flb_buffer_qchunk_signal(FLB_BUFFER_QC_POP_REQUEST, task->ref_id,
                                     task->config->buffer_ctx->qworker);
        }
    }
#endif

    if (task->dt) {
        flb_input_dyntag_destroy(task->dt);
    }


    /* Remove 'retries' */
    mk_list_foreach_safe(head, tmp, &task->retries) {
        retry = mk_list_entry(head, struct flb_task_retry, _head);
        flb_task_retry_destroy(retry);
    }

    flb_input_buf_size_set(task->i_ins);

    flb_free(task->tag);
    flb_free(task);
}

/* Register a thread into the tasks list */
void flb_task_add_thread(struct flb_thread *thread,
                         struct flb_task *task)
{
    struct flb_output_thread *out_th;

    /*
     * It's likely a previous thread have marked this task ready to be deleted,
     * we must check this usual condition that could happen when one input_create
     * instance must flush the data to many destinations.
     */
#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_lock(&task->mutex_threads);
#endif

    out_th = (struct flb_output_thread *) FLB_THREAD_DATA(thread);

    /* Always set an incremental thread_id */
    out_th->id = task->n_threads;
    task->n_threads++;
    task->users++;
    mk_list_add(&out_th->_head, &task->threads);

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_unlock(&task->mutex_threads);
#endif
}
