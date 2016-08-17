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

#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_task.h>

void flb_task_add_thread(struct flb_thread *thread,
                                struct flb_task *task);

#ifdef FLB_HAVE_FLUSH_UCONTEXT

/* It creates a new output thread using a 'Retry' context */
int flb_engine_dispatch_retry(struct flb_task_retry *retry,
                              struct flb_config *config)
{
    struct flb_thread *th;
    struct flb_task *task;
    struct flb_intput_instance *i_ins;

    task = retry->parent;
    i_ins = task->i_ins;

    th = flb_output_thread(task,
                           i_ins,
                           retry->o_ins,
                           config,
                           task->buf, task->size,
                           task->tag,
                           strlen(task->tag));
    if (!th) {
        return -1;
    }

    flb_task_add_thread(th, task);
    flb_thread_resume(th);

    return 0;
}

/*
 * The engine dispatch is responsible for:
 *
 * - Get records from input plugins (fixed tags and dynamic tags)
 * - For each set of records under the same tag, create a Task. A Task set
 *   a reference to the records and routes through output instances.
 */
int flb_engine_dispatch(struct flb_input_instance *in,
                        struct flb_config *config)
{
    char *buf;
    size_t size;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *r_head;
    struct flb_input_plugin *p;
    struct flb_task *task = NULL;
    struct flb_thread *th;
    struct flb_task_route *route;

    p = in->p;
    if (p->cb_flush_buf) {
        buf = p->cb_flush_buf(in->context, &size);
        if (!buf || size == 0) {
            return 0;
        }

        /*
         * Create an engine task, the task will hold the buffer reference
         * and the co-routines associated to the output instance plugins
         * that needs to handle the data.
         */
        task = flb_task_create(buf, size, in, NULL, in->tag, config);
        if (!task) {
            free(buf);
            return -1;
        }
        flb_trace("[engine dispatch] task created %p", task);
    }
    else if (p->flags & FLB_INPUT_DYN_TAG) {
        /* Iterate dynamic tag buffers */
        struct mk_list *d_head, *tmp;
        struct flb_input_dyntag *dt;

        mk_list_foreach_safe(d_head, tmp, &in->dyntags) {
            dt = mk_list_entry(d_head, struct flb_input_dyntag, _head);
            flb_trace("[dyntag %s] %p tag=%s", dt->in->name, dt, dt->tag);

            /* There is a match, get the buffer */
            buf = flb_input_dyntag_flush(dt, &size);
            if (size == 0) {
                if (buf) {
                    free(buf);
                }
                continue;
            }
            if (!buf) {
                continue;
            }

            task = flb_task_create(buf, size, dt->in, dt, dt->tag, config);
            if (!task) {
                free(buf);
                continue;
            }
        }
    }

    /* At this point the input instance should have some tasks linked */
    mk_list_foreach_safe(head, tmp, &in->tasks) {
        task = mk_list_entry(head, struct flb_task, _head);

        /* Only process recently created tasks */
        if (task->status != FLB_TASK_NEW) {
            continue;
        }
        task->status = FLB_TASK_RUNNING;

        /* A task contain one or more routes */
        mk_list_foreach(r_head, &task->routes) {
            route = mk_list_entry(r_head, struct flb_task_route, _head);

            /*
             * We have the Task and the Route, created a thread context for the
             * data handling.
             */
            th = flb_output_thread(task,
                                   in,
                                   route->out,
                                   config,
                                   task->buf, task->size,
                                   task->tag,
                                   strlen(task->tag));
            flb_task_add_thread(th, task);
            flb_thread_resume(th);
        }
    }

    return 0;
}

#elif defined FLB_HAVE_FLUSH_PTHREADS

int flb_engine_dispatch(struct flb_input_instance *in,
                        struct flb_config *config)
{
    char *buf;
    size_t size;
    struct mk_list *r_head;
    struct flb_input_plugin *p;
    struct flb_task *task;
    struct flb_router_path *path;
    struct flb_output_instance *o_ins;
    struct flb_thread *th;

    p = in->p;
    if (p->cb_flush_buf) {
        buf = p->cb_flush_buf(in->context, &size);
        if (!buf || size == 0) {
            return 0;
        }

        /*
         * Create an engine task, the task will hold the buffer reference
         * and the co-routines associated to the output instance plugins
         * that needs to handle the data.
         */
        task = flb_task_create(buf, size, in, in->tag, config);
        if (!task) {
            free(buf);
            return -1;
        }

        /* Create a thread context for an output plugin call */
        mk_list_foreach(r_head, &in->routes) {
            path = mk_list_entry(r_head, struct flb_router_path, _head);
            o_ins = path->ins;

            th = flb_output_thread(task,
                                   in,
                                   o_ins,
                                   config,
                                   buf, size,
                                   in->tag,
                                   in->tag_len);
            flb_task_add_thread(&th->_head, task);
            flb_thread_resume(th);
        }
    }
    else if (p->flags & FLB_INPUT_DYN_TAG) {
        /* Iterate dynamic tag buffers */
        struct mk_list *d_head, *tmp;
        struct flb_input_dyntag *dt;
        struct flb_output_instance *o_ins;

        mk_list_foreach_safe(d_head, tmp, &in->dyntags) {
            int matches = 0;
            struct mk_list *o_head;
            dt = mk_list_entry(d_head, struct flb_input_dyntag, _head);
            flb_trace("[dyntag %s] %p tag=%s", dt->in->name, dt, dt->tag);

            /* There is a match, get the buffer */
            buf = flb_input_dyntag_flush(dt, &size);
            if (size == 0 || !buf) {
                continue;
            }

            task = flb_task_create(buf, size, dt->in, dt,
                                          dt->tag, config);
            if (!task) {
                free(buf);
                continue;
            }

            mk_list_foreach(o_head, &config->outputs) {
                o_ins = mk_list_entry(o_head,
                                      struct flb_output_instance, _head);

                if (flb_router_match(dt->tag, o_ins->match)) {
                    flb_trace("[dyntag %s] [%p] match rule %s:%s",
                              dt->in->name, dt, dt->tag, o_ins->match);

                    flb_trace("[dyntag buf] size=%lu buf=%p",
                              size, buf);

                    th = flb_output_thread(task,
                                           dt->in,
                                           o_ins,
                                           config,
                                           buf, size,
                                           dt->tag, dt->tag_len);

                    /* Associate the thread with the parent task and resume */
                    flb_task_add_thread(&th->_head, task);
                    flb_thread_resume(th);

                    matches++;
                }
            }
            if (matches == 0) {
                flb_input_dyntag_destroy(dt);
            }
        }
    }

    if (p->cb_flush_end) {
        p->cb_flush_end(in->context);
    }

    return 0;
}


#endif /* !FLB_HAVE_FLUSH_UCONTEXT */
