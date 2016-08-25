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

#include <stdio.h>
#include <stdlib.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_task.h>

#ifdef FLB_HAVE_BUFFERING
#include <fluent-bit/flb_sha1.h>
#include <fluent-bit/flb_buffer_chunk.h>
#endif

/*
 * Every task created must have an unique ID, this function lookup the
 * lowest number available in the tasks_map.
 *
 * This 'id' is used by the task interface to communicate with the engine event
 * loop about some action.
 */

static int map_get_task_id(struct flb_config *config)
{
    int i;

    for (i = 0; i < sizeof(config->tasks_map); i++) {
        if (config->tasks_map[i].task == NULL) {
            return i;
        }
    }

    return -1;
}

static void map_set_task_id(int id, struct flb_task *task,
                            struct flb_config *config)
{
    config->tasks_map[id].task = task;

}

struct flb_task_retry *flb_task_retry_create(struct flb_task *task,
                                             struct flb_output_instance *o_ins)
{
    struct flb_task_retry *retry;

    retry = malloc(sizeof(struct flb_task_retry));
    if (!retry) {
        perror("malloc");
        return NULL;
    }

    retry->attemps = 1;     /* It already failed once, that's why we are here */
    retry->o_ins   = o_ins;
    retry->parent  = task;
    mk_list_add(&retry->_head, &task->retries);

    return retry;
}

/* Create an engine task to handle the output plugin flushing work */
struct flb_task *flb_task_create(char *buf,
                                 size_t size,
                                 struct flb_input_instance *i_ins,
                                 struct flb_input_dyntag *dt,
                                 char *tag,
                                 struct flb_config *config)
{
    int count = 0;
    int task_id;
    uint64_t routes_mask = 0;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_output_instance *o_ins;
    struct flb_router_path *router_path;
    struct mk_list *head;
    struct mk_list *o_head;

    /* Allocate the new task */
    task = (struct flb_task *) calloc(1, sizeof(struct flb_task));
    if (!task) {
        perror("malloc");
        return NULL;
    }

    /* Get ID and set back 'task' reference */
    task_id = map_get_task_id(config);
    if (task_id == -1) {
        free(task);
        return NULL;
    }
    map_set_task_id(task_id, task, config);

    /* Keep track of origins */
    task->id        = task_id;
    task->status    = FLB_TASK_NEW;
    task->n_threads = 0;
    task->users     = 0;
    task->tag       = strdup(tag);
    task->buf       = buf;
    task->size      = size;
    task->i_ins     = i_ins;
    task->dt        = dt;
    task->config    = config;
    mk_list_init(&task->threads);
    mk_list_init(&task->routes);
    mk_list_init(&task->retries);
    mk_list_add(&task->_head, &i_ins->tasks);

    /* Routes */
    if (!dt) {
        /* A non-dynamic tag input plugin have static routes */
        mk_list_foreach(head, &i_ins->routes) {
            router_path = mk_list_entry(head, struct flb_router_path, _head);
            o_ins = router_path->ins;

            route = malloc(sizeof(struct flb_task_route));
            if (!route) {
                perror("malloc");
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

            if (flb_router_match(tag, o_ins->match)) {
                route = malloc(sizeof(struct flb_task_route));
                if (!route) {
                    perror("malloc");
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

#ifdef FLB_HAVE_BUFFERING
    int i;
    int worker_id;

    /* Generate content SHA1 and it Hexa representation */
    flb_sha1_encode(buf, size, &task->hash_sha1);
    for (i = 0; i < 20; ++i) {
        sprintf(&task->hash_hex[i*2], "%02x", task->hash_sha1[i]);
    }
    task->hash_hex[40] = '\0';

    /*
     * Generate a buffer chunk push request, note that suggested routes
     * are passed through the 'routes_mask' bit mask variable.
     */
    worker_id = flb_buffer_chunk_push(config->buffer_ctx, buf, size, tag,
                                      routes_mask, &task->hash_hex);

    task->worker_id = worker_id;
    flb_debug("[task->buffer] worker_id=%i", worker_id);
#endif

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_init(&task->mutex_threads, NULL);
#endif

    return task;
}

void flb_task_destroy(struct flb_task *task)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_task_route *route;

    flb_trace("[engine] destroy task_id=%i", task->id);

    if (task->dt) {
        flb_input_dyntag_destroy(task->dt);
    }

    /* Release task_id */
    task->config->tasks_map[task->id].task = NULL;

    /* Remove routes */
    mk_list_foreach_safe(head, tmp, &task->routes) {
        route = mk_list_entry(head, struct flb_task_route, _head);
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
void flb_task_add_thread(struct flb_thread *thread,
                         struct flb_task *task)
{
    /*
     * It's likely a previous thread have marked this task ready to be deleted,
     * we must check this usual condition that could happen when one input
     * instance must flush the data to many destinations.
     */
#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_lock(&task->mutex_threads);
#endif

    /* Always set an incremental thread_id */
    thread->id = task->n_threads;
    task->n_threads++;
    task->users++;
    mk_list_add(&thread->_head, &task->threads);

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_unlock(&task->mutex_threads);
#endif
}
