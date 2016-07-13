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
#include <fluent-bit/flb_engine_task.h>

/* Create an engine task to handle the output plugin flushing work */
struct flb_engine_task *flb_engine_task_create(char *buf,
                                               size_t size,
                                               struct flb_input_instance *i_ins,
                                               struct flb_input_dyntag *dt,
                                               char *tag,
                                               struct flb_config *config)
{
    int count = 0;
    uint64_t routes_mask = 0;
    struct flb_engine_task *task;
    struct flb_engine_task_route *route;
    struct flb_output_instance *o_ins;
    struct flb_router_path *router_path;
    struct mk_list *head;
    struct mk_list *o_head;

    /* Allocate the new task */
    task = (struct flb_engine_task *) calloc(1, sizeof(struct flb_engine_task));
    if (!task) {
        perror("malloc");
        return NULL;
    }

    /* Keep track of origins */
    task->status  = FLB_ENGINE_TASK_NEW;
    task->deleted = FLB_FALSE;
    task->users   = 0;
    task->tag     = strdup(tag);
    task->buf     = buf;
    task->size    = size;
    task->i_ins   = i_ins;
    task->dt      = dt;
    mk_list_init(&task->threads);
    mk_list_init(&task->routes);
    mk_list_add(&task->_head, &i_ins->tasks);

    /* Routes */
    if (!dt) {
        /* A non-dynamic tag input plugin have static routes */
        mk_list_foreach(head, &i_ins->routes) {
            router_path = mk_list_entry(head, struct flb_router_path, _head);
            o_ins = router_path->ins;

            route = malloc(sizeof(struct flb_engine_task_route));
            if (!route) {
                perror("malloc");
                continue;
            }

            route->out = o_ins;
            mk_list_add(&route->_head, &task->routes);
            count++;

        }
    }
    else {
        /* Find dynamic routes for the incoming tag */
        mk_list_foreach(o_head, &config->outputs) {
            o_ins = mk_list_entry(o_head,
                                  struct flb_output_instance, _head);

            if (flb_router_match(tag, o_ins->match)) {
                route = malloc(sizeof(struct flb_engine_task_route));
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

    /*
     * FIXME: Testing the task interface to enqueue buffer chunks
     */
#ifdef FLB_HAVE_BUFFERING
    uint64_t cid;

    /*
     * Generate a buffer chunk push request, note that suggested routes
     * are passed through the 'routes_mask' bit mask variable.
     */
    cid = flb_buffer_chunk_push(config->buffer_ctx,
                                buf, size, tag, routes_mask);
    flb_debug("[task->buffer] new chunk=%lu", cid);
#endif

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_init(&task->mutex_threads, NULL);
#endif

    return task;
}
