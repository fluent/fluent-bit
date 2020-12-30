/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_output_thread.h>
#include <fluent-bit/flb_thread_pool.h>

struct thread_instance {
    struct mk_event event;               /* event context to associate events */
    flb_pipefd_t ch_parent_events[2];    /* channel to receive parent notifications */
    flb_pipefd_t ch_thread_events[2];    /* channel to send messages to main engine */
    struct flb_output_instance *ins;     /* output plugin instance */
    struct flb_config *config;
    struct flb_tp_thread *th;
    struct mk_list _head;
};

/* Cleanup function that runs every 1.5 second */
static void cb_thread_sched_timer(struct flb_config *ctx, void *data)
{
    (void) ctx;
    struct flb_output_instance *ins;

    /* Upstream connections timeouts handling */
    ins = (struct flb_output_instance *) data;
    flb_upstream_conn_timeouts(&ins->upstreams);
}

/*
 * This is the worker function that creates an event loop and synchronize
 * messages from the engine like 'flush' requests. Note that the running
 * plugin flush callback has not notion about it threaded context.
 *
 * Each worker spawn a co-routine per flush request.
 */
static void output_thread(void *data)
{
    int n;
    int ret;
    int running = FLB_TRUE;
    int thread_id;
    void *ptr;
    char tmp[64];
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct flb_sched *sched;
    struct flb_coro *co;
    struct flb_task *task;
    struct flb_upstream_conn *u_conn;
    struct flb_output_instance *ins;
    struct thread_instance *th_ins = (struct thread_instance *) data;


    ins = th_ins->ins;
    thread_id = th_ins->th->id;

    /* Create the event loop for this thread */
    evl = mk_event_loop_create(64);
    if (!evl) {
        flb_plg_error(ins, "could not create thread event loop");
        return;
    }

    /* Create a scheduler context */
    sched = flb_sched_create(ins->config, evl);
    if (!sched) {
        flb_plg_error(ins, "could not create thread scheduler");
        mk_event_loop_destroy(evl);
        return;
    }

    /*
     * Sched a permanent callback triggered every 1.5 second to let other
     * components of this thread run tasks at that interval.
     */
    ret = flb_sched_timer_cb_create(sched,
                                    FLB_SCHED_TIMER_CB_PERM,
                                    1500, cb_thread_sched_timer, ins);
    if (ret == -1) {
        flb_plg_error(ins, "could not schedule permanent callback");
        return;
    }

    snprintf(tmp, sizeof(tmp) - 1, "flb-out-%s-w%i", ins->name, thread_id);
    mk_utils_worker_rename(tmp);

    /*
     * Expose the event loop to the I/O interfaces: since we are in a separate
     * thread, the upstream connection interfaces need access to the event
     * loop for event notifications. Invoking the flb_engine_evl_set() function
     * it sets the event loop reference in a TLS (thread local storage) variable
     * of the scope of this thread.
     */
    flb_engine_evl_set(evl);

    /*
     * Event loop setup between parent engine and this thread
     *
     *  - FLB engine uses 'ch_parent_events[1]' to dispatch tasks to this thread
     *  - Thread receive message on ch_parent_events[0]
     *
     * The mk_event_channel_create() will attach the pipe read end ch_parent_events[0]
     * to the local event loop 'evl'.
     */
    ret = mk_event_channel_create(evl,
                                  &th_ins->ch_parent_events[0],
                                  &th_ins->ch_parent_events[1],
                                  th_ins);
    if (ret == -1) {
        flb_plg_error(th_ins->ins, "could not create thread channel");
        flb_engine_evl_set(NULL);
        mk_event_loop_destroy(evl);
        return;
    }
    th_ins->event.type = FLB_ENGINE_EV_THREAD_OUTPUT;

    flb_plg_info(th_ins->ins, "worker #%i started", thread_id);

    /* Thread event loop */
    while (running) {
        mk_event_wait(evl);
        mk_event_foreach(event, evl) {
            /*
             * FIXME
             * -----
             * - handle return status by plugin flush callback.
             */
            if (event->type == FLB_ENGINE_EV_CORE) {

            }
            else if (event->type & FLB_ENGINE_EV_SCHED) {
                /* Note that this scheduler event handler has more
                 * features designed to be used from the parent thread,
                 * on this specific use case we just care about simple
                 * timers created on this thread or threaded by some
                 * output plugin.
                 */
                flb_sched_event_handler(sched->config, event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD_OUTPUT) {

                n = flb_pipe_r(event->fd, &task, sizeof(struct flb_task *));

                if ((uint64_t) task == 0xdeadbeef) {
                    running = FLB_FALSE;
                    continue;
                }

                co = flb_output_thread(task,
                                       task->i_ins,
                                       th_ins->ins,
                                       th_ins->config,
                                       task->buf, task->size,
                                       task->tag,
                                       task->tag_len);
                if (!co) {
                    continue;
                }

                flb_task_add_thread(co, task);
                flb_coro_resume(co);
            }
            else if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD) {
                /*
                 * Check if we have some co-routine associated to this event,
                 * if so, resume the co-routine
                 */
                u_conn = (struct flb_upstream_conn *) event;
                co = u_conn->coro;
                if (co) {
                    flb_trace("[engine] resuming coroutine=%p", co);
                    flb_coro_resume(co);
                }
            }
            else {
                flb_plg_warn(ins, "unhandled event type => %i\n", event->type);
            }
        }

        flb_upstream_conn_pending_destroy_list(&ins->upstreams);
    }

    flb_plg_info(ins, "thread worker #%i stopped", thread_id);
}

int flb_output_thread_pool_flush(struct flb_task *task,
                                 struct flb_output_instance *out_ins,
                                 struct flb_config *config)
{
    int n;
    struct flb_tp_thread *th;
    struct flb_tp *tp = out_ins->tp;
    struct thread_instance *th_ins;

    /* Choose the worker that will handle the Task (round-robin) */
    th = flb_tp_thread_get_rr(out_ins->tp);
    if (!th) {
        return -1;
    }

    th_ins = th->params.data;

    flb_plg_debug(out_ins, "task_id=%i assigned to thread #%i",
                  task->id, th->id);
    n = write(th_ins->ch_parent_events[1], &task, sizeof(struct flb_task *));
    if (n == -1) {
        flb_errno();
    }

}

int flb_output_thread_pool_create(struct flb_config *config,
                                  struct flb_output_instance *ins)
{
    int i;
    int ret;
    struct flb_tp *tp;
    struct flb_tp_thread *th;
    struct thread_instance *th_ins;

    tp = flb_tp_create(config);
    if (!tp) {
        return -1;
    }
    ins->tp = tp;

    for (i = 0; i < ins->tp_workers; i++) {
        th_ins = flb_malloc(sizeof(struct thread_instance));
        if (!th_ins) {
            flb_errno();
            continue;
        }
        th_ins->config = config;

        /*
         * Create the communication channel: each created thread has two pairs
         * of pipes, one to receive messages from the parent engine, and another
         * to send messages back.
         *
         * Here we just create the channel to receive messages from the parent
         * engine (the other pipe is set inside the thread).
         *
         * Map:
         *
         * 1.
         *  - FLB engine uses 'ch_parent_events[1]' to dispatch tasks to thread
         *  - Thread receive message on ch_parent_events[0]
         *
         */
        ret = mk_event_channel_create(config->evl,
                                      &th_ins->ch_parent_events[0],
                                      &th_ins->ch_parent_events[1],
                                      th_ins);
        if (ret != 0) {
            flb_plg_error(ins, "could not create event channels for thread #%i",
                          i);
            flb_free(th_ins);
            continue;
        }

        /* Override the event notification type */
        th_ins->event.type = FLB_ENGINE_EV_THREAD_OUTPUT;
        th_ins->ins = ins;

        /* Spawn the thread */
        th = flb_tp_thread_create(tp, output_thread, th_ins, config);
        if (!th) {
            flb_plg_error(ins, "could not register worker thread #%i", i);
            continue;
        }
        th_ins->th = th;
    }

    return 0;
}

void flb_output_thread_pool_destroy(struct flb_output_instance *ins)
{
    int n;
    uint64_t stop = 0xdeadbeef;
    struct flb_tp *tp = ins->tp;
    struct mk_list *head;
    struct thread_instance *th_ins;
    struct flb_tp_thread *th;

    if (!tp) {
        return;
    }

    /* Signal each worker thread that needs to stop doing work */
    mk_list_foreach(head, &tp->list_threads) {
        th = mk_list_entry(head, struct flb_tp_thread, _head);
        if (th->status != FLB_THREAD_POOL_RUNNING) {
            continue;
        }

        th_ins = th->params.data;
        n = write(th_ins->ch_parent_events[1], &stop, sizeof(stop));
        pthread_join(th->tid, NULL);
        flb_free(th_ins);
    }

    flb_tp_destroy(ins->tp);
    ins->tp = NULL;
}

int flb_output_thread_pool_start(struct flb_output_instance *ins)
{
    struct flb_tp *tp = ins->tp;

    flb_tp_thread_start_all(tp);
    return 0;
}
