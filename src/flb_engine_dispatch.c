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

#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_event.h>
#include <chunkio/chunkio.h>


/* It creates a new output thread using a 'Retry' context */
int flb_engine_dispatch_retry(struct flb_task_retry *retry,
                              struct flb_config *config)
{
    int ret;
    char *buf_data;
    size_t buf_size;
    struct flb_task *task;

    task = retry->parent;

    /* Set file up/down based on restrictions */
    ret = flb_input_chunk_set_up(task->ic);
    if (ret == -1) {
        /*
         * The re-try is not possible. The chunk is not in memory and trying to bringing it
         * up was not possible.
         *
         * A common cause for this is that the Chunk I/O system is not draining fast
         * enough like errors on delivering data. So if we cannot put the chunk in memory
         * it cannot be retried.
         */
        ret = flb_task_retry_reschedule(retry, config);
        if (ret == -1) {
            return -1;
        }

        /* Just return because it has been re-scheduled */
        return 0;
    }

    /* There is a match, get the buffer */
    buf_data = (char *) flb_input_chunk_flush(task->ic, &buf_size);
    if (!buf_data) {
        /* Could not retrieve chunk content */
        flb_error("[engine_dispatch] could not retrieve chunk content, removing retry");
        flb_task_retry_destroy(retry);
        return -1;
    }

    /* Update the buffer reference */
    flb_event_chunk_update(task->event_chunk, buf_data, buf_size);

    /* flush the task */
    if (retry->o_ins->flags & FLB_OUTPUT_SYNCHRONOUS) {
        /*
         * If the plugin doesn't allow for multiplexing.
         * singleplex_enqueue deletes retry context on flush or delayed flush failure
         */
        ret = flb_output_task_singleplex_enqueue(retry->o_ins->singleplex_queue, retry,
                                                 task, retry->o_ins, config);
        if (ret == -1) {
            return -1;
        }
    }
    else {
        ret = flb_output_task_flush(task, retry->o_ins, config);
        if (ret == -1) {
            flb_task_retry_destroy(retry);
            return -1;
        }
    }

    return 0;
}

static void test_run_formatter(struct flb_config *config,
                               struct flb_input_instance *i_ins,
                               struct flb_output_instance *o_ins,
                               struct flb_task *task)
{
    int ret;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_test_out_formatter *otf;
    struct flb_event_chunk *evc;
    void *flush_ctx;

    otf = &o_ins->test_formatter;
    evc = task->event_chunk;

    flush_ctx = otf->flush_ctx;
    if (otf->flush_ctx_callback) {
        flush_ctx = otf->flush_ctx_callback(config, i_ins, o_ins->context, flush_ctx);
    }

    /* Invoke the output plugin formatter test callback */
    ret = otf->callback(config,
                        i_ins,
                        o_ins->context,
                        flush_ctx,
                        evc->type,
                        evc->tag, flb_sds_len(evc->tag),
                        evc->data, evc->size,
                        &out_buf, &out_size);

    /* Call the runtime test callback checker */
    if (otf->rt_out_callback) {
        otf->rt_out_callback(otf->rt_ctx,
                             otf->rt_ffd,
                             ret,
                             out_buf, out_size,
                             otf->rt_data);
    }
    else {
        flb_free(out_buf);
    }
}

static int tasks_start(struct flb_input_instance *in,
                       struct flb_config *config)
{
    int hits = 0;
    int retry = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *r_head;
    struct mk_list *r_tmp;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_output_instance *out;

    /* At this point the input instance should have some tasks linked */
    mk_list_foreach_safe(head, tmp, &in->tasks) {
        task = mk_list_entry(head, struct flb_task, _head);

        if (mk_list_is_empty(&task->retries) != 0) {
            retry++;
        }

        /* Only process recently created tasks */
        if (task->status != FLB_TASK_NEW) {
            continue;
        }
        task->status = FLB_TASK_RUNNING;

        /* A task contain one or more routes */
        mk_list_foreach_safe(r_head, r_tmp, &task->routes) {
            route = mk_list_entry(r_head, struct flb_task_route, _head);

            /*
             * Test mode: if the output plugin is in test mode, just invoke
             * the proper test function and continue;
             */
            out = route->out;
            if (out->test_mode == FLB_TRUE &&
                out->test_formatter.callback != NULL) {

                /* Run the formatter test */
                test_run_formatter(config, in, out, task);

                /* Remove the route */
                mk_list_del(&route->_head);
                flb_free(route);
                continue;
            }

            /*
             * If the plugin don't allow multiplexing Tasks, check if it's
             * running something.
             */
            if (out->flags & FLB_OUTPUT_NO_MULTIPLEX) {
                if (flb_output_coros_size(route->out) > 0 || retry > 0) {
                    continue;
                }
            }

            hits++;

            /*
             * If the plugin is in synchronous mode, enqueue the task and flush
             * when appropriate.
             */
            if (out->flags & FLB_OUTPUT_SYNCHRONOUS) {
                flb_output_task_singleplex_enqueue(route->out->singleplex_queue, NULL,
                                                   task, route->out, config);
            }
            else {
                /*
                 * We have the Task and the Route, created a thread context for the
                 * data handling.
                 */
                flb_output_task_flush(task, route->out, config);
            }

            /*
            th = flb_output_thread(task,
                                   in,
                                   route->out,
                                   config,
                                   task->buf, task->size,
                                   task->tag,
                                   task->tag_len);
            flb_task_add_thread(th, task);
            flb_thread_resume(th);
            */
        }

        if (hits == 0) {
            task->status = FLB_TASK_NEW;
        }

        hits = 0;
    }

    return 0;
}

/*
 * The engine dispatch is responsible for:
 *
 * - Get chunks generated by input plugins.
 * - For each set of records under the same tag, create a Task. A Task set
 *   a reference to the records and routes through output instances.
 */
int flb_engine_dispatch(uint64_t id, struct flb_input_instance *in,
                        struct flb_config *config)
{
    int ret;
    int t_err;
    const char *buf_data;
    size_t buf_size = 0;
    const char *tag_buf;
    int tag_len;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_plugin *p;
    struct flb_input_chunk *ic;
    struct flb_task *task = NULL;

    p = in->p;
    if (!p) {
        return 0;
    }

    /* Look for chunks ready to go */
    mk_list_foreach_safe(head, tmp, &in->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        if (ic->busy == FLB_TRUE) {
            continue;
        }

        if (flb_task_map_get_task_id(config) == -1) {
            /*
             * There isn't a task available, no more chunks can have a task
             * assigned.
             */
            break;
        }

        /* There is a match, get the buffer */
        buf_data = flb_input_chunk_flush(ic, &buf_size);
        if (buf_size == 0) {
            /*
             * Do not release the buffer since if allocated, it will be
             * released when the task is destroyed.
             */
            flb_input_chunk_release_lock(ic);
            continue;
        }
        if (!buf_data) {
            flb_input_chunk_release_lock(ic);
            continue;
        }

        /* Get the the tag reference (chunk metadata) */
        ret = flb_input_chunk_get_tag(ic, &tag_buf, &tag_len);
        if (ret == -1) {
            flb_input_chunk_release_lock(ic);
            continue;
        }

        /* Validate outgoing Tag information */
        if (!tag_buf || tag_len <= 0) {
            flb_input_chunk_release_lock(ic);
            continue;
        }

        /* Create a task */
        task = flb_task_create(id, buf_data, buf_size,
                               ic->in, ic,
                               tag_buf, tag_len,
                               config, &t_err);
        if (!task) {
            /*
             * If task creation failed, check the error status flag. An error
             * is associated with memory allocation or exhaustion of tasks_id,
             * on that case the input chunk must be preserved and retried
             * later. So we just release it busy lock.
             */
            if (t_err == FLB_TRUE) {
                flb_input_chunk_release_lock(ic);

                /*
                 * If the Storage type is 'filesystem' we need to put
                 * the file content down.
                 */
                flb_input_chunk_down(ic);
            }
            continue;
        }
    }

    /* Start the new enqueued Tasks */
    tasks_start(in, config);

    /*
     * Tasks cleanup: if some tasks are associated to output plugins running
     * in test mode, they must be cleaned up since they do not longer contains
     * an outgoing route.
     */
    mk_list_foreach_safe(head, tmp, &in->tasks) {
        task = mk_list_entry(head, struct flb_task, _head);
        if (task->users == 0 &&
            mk_list_size(&task->retries) == 0 &&
            mk_list_size(&task->routes) == 0) {
            flb_info("[task] cleanup test task");
            flb_task_destroy(task, FLB_TRUE);
        }
    }

    return 0;
}
