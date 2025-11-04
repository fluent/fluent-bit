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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_output_thread.h>
#include <fluent-bit/flb_thread_pool.h>
#include <fluent-bit/flb_notification.h>

static pthread_once_t local_thread_instance_init = PTHREAD_ONCE_INIT;
FLB_TLS_DEFINE(struct flb_out_thread_instance, local_thread_instance);

void flb_output_thread_instance_init()
{
    FLB_TLS_INIT(local_thread_instance);
}

struct flb_out_thread_instance *flb_output_thread_instance_get()
{
    struct flb_out_thread_instance *th_ins;

    th_ins = FLB_TLS_GET(local_thread_instance);
    return th_ins;
}

void flb_output_thread_instance_set(struct flb_out_thread_instance *th_ins)
{
    FLB_TLS_SET(local_thread_instance, th_ins);
}

/* Cleanup function that runs every 1.5 second */
static void cb_thread_sched_timer(struct flb_config *ctx, void *data)
{
    (void) ctx;
    struct flb_output_instance *ins;

    /* Upstream connections timeouts handling */
    ins = (struct flb_output_instance *) data;
    flb_upstream_conn_timeouts(&ins->upstreams);
}

static inline int handle_output_event(struct flb_config *config,
                                      int ch_parent, flb_pipefd_t fd)
{
    int ret;
    int bytes;
    int out_id;
    uint32_t type;
    uint32_t key;
    uint64_t val;

    bytes = flb_pipe_r(fd, &val, sizeof(val));
    if (bytes == -1) {
        flb_pipe_error();
        return -1;
    }

    /* Get type and key */
    type = FLB_BITS_U64_HIGH(val);
    key  = FLB_BITS_U64_LOW(val);

    if (type != FLB_ENGINE_TASK) {
        flb_error("[engine] invalid event type %i for output handler",
                  type);
        return -1;
    }

    ret     = FLB_TASK_RET(key);
    out_id  = FLB_TASK_OUT(key);

    /* Destroy the output co-routine context */
    flb_output_flush_finished(config, out_id);

    /*
     * Notify the parent event loop the return status, just forward the same
     * 64 bits value.
     */
    ret = flb_pipe_w(ch_parent, &val, sizeof(val));
    if (ret == -1) {
        flb_pipe_error();
        return -1;
    }

    return 0;
}

/*
 * For every upstream registered, creates a local mapping for the thread. This is
 * done to provide local queues of connections so we can use our event loop and I/O
 * totally independently without the need of any syncrhonization across threads
 */
static int upstream_thread_create(struct flb_out_thread_instance *th_ins,
                                  struct flb_output_instance *ins)
{
    struct mk_list *head;
    struct flb_upstream *u;
    struct flb_upstream *th_u;

    mk_list_foreach(head, &ins->upstreams) {
        u = mk_list_entry(head, struct flb_upstream, base._head);

        th_u = flb_calloc(1, sizeof(struct flb_upstream));
        if (!th_u) {
            flb_errno();
            return -1;
        }
        th_u->parent_upstream = u;
        flb_upstream_queue_init(&th_u->queue);
        mk_list_add(&th_u->base._head, &th_ins->upstreams);
    }

    return 0;
}

int count_upstream_busy_connections(struct flb_out_thread_instance *th_ins)
{
    int c = 0;
    struct mk_list *head;
    struct flb_upstream *u;

    mk_list_foreach(head, &th_ins->upstreams) {
        u = mk_list_entry(head, struct flb_upstream, base._head);
        c += mk_list_size(&u->queue.busy_queue);
    }

    return c;
}

static void upstream_thread_destroy(struct flb_out_thread_instance *th_ins)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream *th_u;

    mk_list_foreach_safe(head, tmp, &th_ins->upstreams) {
        th_u = mk_list_entry(head, struct flb_upstream, base._head);
        flb_upstream_destroy(th_u);
    }
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
    int stopping = FLB_FALSE;
    int thread_id;
    char tmp[64];
    struct mk_event event_local;
    struct mk_event *event;
    struct flb_sched *sched;
    struct flb_task *task;
    struct flb_connection *u_conn;
    struct flb_output_instance *ins;
    struct flb_output_flush *out_flush;
    struct flb_out_thread_instance *th_ins = data;
    struct flb_out_flush_params *params;
    struct flb_sched_timer_coro_cb_params *sched_params;
    struct flb_net_dns dns_ctx;
    struct flb_notification *notification;

    /* Register thread instance */
    flb_output_thread_instance_set(th_ins);

    ins = th_ins->ins;
    thread_id = th_ins->th->id;

    flb_coro_thread_init();

    flb_net_ctx_init(&dns_ctx);
    flb_net_dns_ctx_set(&dns_ctx);

    /*
     * Expose the event loop to the I/O interfaces: since we are in a separate
     * thread, the upstream connection interfaces need access to the event
     * loop for event notifications. Invoking the flb_engine_evl_set() function
     * it sets the event loop reference in a TLS (thread local storage) variable
     * of the scope of this thread.
     */
    flb_engine_evl_set(th_ins->evl);

    /* Set the upstream queue */
    flb_upstream_list_set(&th_ins->upstreams);

    /* Create a scheduler context */
    sched = flb_sched_create(ins->config, th_ins->evl);
    if (!sched) {
        flb_plg_error(ins, "could not create thread scheduler");
        return;
    }
    flb_sched_ctx_set(sched);

    /*
     * Sched a permanent callback triggered every 1.5 second to let other
     * components of this thread run tasks at that interval.
     */
    ret = flb_sched_timer_cb_create(sched,
                                    FLB_SCHED_TIMER_CB_PERM,
                                    1500, cb_thread_sched_timer, ins, NULL);
    if (ret == -1) {
        flb_plg_error(ins, "could not schedule permanent callback");
        return;
    }

    snprintf(tmp, sizeof(tmp) - 1, "flb-out-%s-w%i", ins->name, thread_id);
    mk_utils_worker_rename(tmp);

    memset(&event_local, 0, sizeof(struct mk_event));

    /* Channel used by flush callbacks to notify it return status */
    ret = mk_event_channel_create(th_ins->evl,
                                  &th_ins->ch_thread_events[0],
                                  &th_ins->ch_thread_events[1],
                                  &event_local);
    if (ret == -1) {
        flb_plg_error(th_ins->ins, "could not create thread channel");
        flb_engine_evl_set(NULL);
        return;
    }
    event_local.type = FLB_ENGINE_EV_OUTPUT;

    if (ins->p->cb_worker_init) {
        ret = ins->p->cb_worker_init(ins->context, ins->config);
    }

    flb_plg_info(th_ins->ins, "worker #%i started", thread_id);

    /* Thread event loop */
    while (running) {
        mk_event_wait(th_ins->evl);
        flb_event_priority_live_foreach(event, th_ins->evl_bktq, th_ins->evl,
                                         FLB_ENGINE_LOOP_MAX_ITER) {

            /*
             * FIXME
             * -----
             * - handle return status by plugin flush callback.
             */
            if (event->type == FLB_ENGINE_EV_CORE) {

            }
            else if (event->type & FLB_ENGINE_EV_SCHED) {
                /*
                 * Note that this scheduler event handler has more features
                 * designed to be used from the parent thread, on this specific
                 * use case we just care about simple timers created on this
                 * thread or threaded by some output plugin.
                 */
                flb_sched_event_handler(sched->config, event);
            }
            else if (event->type & FLB_ENGINE_EV_SCHED_CORO) {
                /*
                 * Note that this scheduler event handler has more features
                 * designed to be used from the parent thread, on this specific
                 * use case we just care about simple timers created on this
                 * thread or threaded by some output plugin.
                 */
                flb_sched_event_handler(sched->config, event);

            }
            else if (event->type == FLB_ENGINE_EV_THREAD_OUTPUT) {
                /* Read the task reference */
                n = flb_pipe_r(event->fd, &task, sizeof(struct flb_task *));
                if (n <= 0) {
                    flb_pipe_error();
                    continue;
                }
                /*
                 * If the address receives 0xdeadbeef, means the thread must
                 * be terminated.
                 */
                if (task == (struct flb_task *) 0xdeadbeef) {
                    stopping = FLB_TRUE;
                    flb_plg_info(th_ins->ins, "thread worker #%i stopping...",
                                 thread_id);
                    continue;
                }
                else {
                    /* Start the co-routine with the flush callback */
                    out_flush = flb_output_flush_create(task,
                                                        task->i_ins,
                                                        th_ins->ins,
                                                        th_ins->config);
                    if (!out_flush) {
                        continue;
                    }
                    flb_coro_resume(out_flush->coro);
                }
            }
            else if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD) {
                /*
                 * Check if we have some co-routine associated to this event,
                 * if so, resume the co-routine
                 */
                u_conn = (struct flb_connection *) event;

                if (u_conn->coroutine) {
                    flb_trace("[engine] resuming coroutine=%p", u_conn->coroutine);
                    flb_coro_resume(u_conn->coroutine);
                }
            }
            else if (event->type == FLB_ENGINE_EV_OUTPUT) {
                /*
                 * The flush callback has finished working and delivered it
                 * return status. At this intermediary step we cleanup the
                 * co-routine resources created before and then forward
                 * the return message to the parent event loop so the Task
                 * can be updated.
                 */
                handle_output_event(th_ins->config, ins->ch_events[1], event->fd);
            }
            else if(event->type == FLB_ENGINE_EV_NOTIFICATION) {
                ret = flb_notification_receive(event->fd, &notification);

                if (ret == 0) {
                    ret = flb_notification_deliver(notification);

                    flb_notification_cleanup(notification);
                }
            }
            else {
                flb_plg_warn(ins, "unhandled event type => %i\n", event->type);
            }
        }

        flb_net_dns_lookup_context_cleanup(&dns_ctx);

        /* Destroy upstream connections from the 'pending destroy list' */
        flb_upstream_conn_pending_destroy_list(&th_ins->upstreams);

        flb_sched_timer_cleanup(sched);

        /* Check if we should stop the event loop */
        if (stopping == FLB_TRUE && mk_list_size(&th_ins->flush_list) == 0) {
            /*
             * If there are no busy network connections (and no coroutines) its
             * safe to stop it.
             */
            if (count_upstream_busy_connections(th_ins) == 0) {
                running = FLB_FALSE;
            }
        }
    }

    if (ins->p->cb_worker_exit) {
        ret = ins->p->cb_worker_exit(ins->context, ins->config);
    }

    mk_event_channel_destroy(th_ins->evl,
                             th_ins->ch_thread_events[0],
                             th_ins->ch_thread_events[1],
                             &event_local);
    /*
     * Final cleanup, destroy all resources associated with:
     *
     * - local upstream maps
     * - available connections, likely these are unused keepalive connections
     * - any 'new' connection in the pending destroy list
     * - event loop context
     * - scheduler context
     * - parameters helper for coroutines
     */
    upstream_thread_destroy(th_ins);
    flb_upstream_conn_active_destroy_list(&th_ins->upstreams);
    flb_upstream_conn_pending_destroy_list(&th_ins->upstreams);

    flb_sched_destroy(sched);
    params = FLB_TLS_GET(out_flush_params);
    if (params) {
        flb_free(params);
        FLB_TLS_SET(out_flush_params, NULL);
    }

    sched_params = (struct flb_sched_timer_coro_cb_params *) FLB_TLS_GET(sched_timer_coro_cb_params);
    if (sched_params != NULL && sched_params->magic == FLB_SCHED_TLS_MAGIC) {
        flb_free(sched_params);
        FLB_TLS_SET(sched_timer_coro_cb_params, NULL);
    }


    mk_event_channel_destroy(th_ins->evl,
                             th_ins->ch_parent_events[0],
                             th_ins->ch_parent_events[1],
                             th_ins);

    if (th_ins->notification_channels_initialized == FLB_TRUE) {
        mk_event_channel_destroy(th_ins->evl,
                                 th_ins->notification_channels[0],
                                 th_ins->notification_channels[1],
                                 &th_ins->notification_event);

        th_ins->notification_channels_initialized = FLB_FALSE;
    }

    mk_event_loop_destroy(th_ins->evl);
    flb_bucket_queue_destroy(th_ins->evl_bktq);

    flb_plg_info(ins, "thread worker #%i stopped", thread_id);
}

int flb_output_thread_pool_flush(struct flb_task *task,
                                 struct flb_output_instance *out_ins,
                                 struct flb_config *config)
{
    int n;
    struct flb_tp_thread *th;
    struct flb_out_thread_instance *th_ins;

    /* Choose the worker that will handle the Task (round-robin) */
    th = flb_tp_thread_get_rr(out_ins->tp);
    if (!th) {
        return -1;
    }

    th_ins = th->params.data;

    flb_plg_debug(out_ins, "task_id=%i assigned to thread #%i",
                  task->id, th->id);

    n = flb_pipe_w(th_ins->ch_parent_events[1], &task, sizeof(struct flb_task*));

    if (n == -1) {
        flb_pipe_error();
        return -1;
    }

    return 0;
}

int flb_output_thread_pool_create(struct flb_config *config,
                                  struct flb_output_instance *ins)
{
    int i;
    int ret;
    struct flb_tp *tp;
    struct flb_tp_thread *th;
    struct mk_event_loop *evl;
    struct flb_bucket_queue *evl_bktq;
    struct flb_out_thread_instance *th_ins;

    /* Create the thread pool context */
    tp = flb_tp_create(config);
    if (!tp) {
        return -1;
    }
    ins->tp = tp;
    ins->is_threaded = FLB_TRUE;

    /*
     * Initialize thread-local-storage, every worker thread has it owns
     * context with relevant info populated inside the thread.
     */
    pthread_once(&local_thread_instance_init, flb_output_thread_instance_init);

    /* Create workers */
    for (i = 0; i < ins->tp_workers; i++) {
        th_ins = flb_malloc(sizeof(struct flb_out_thread_instance));
        if (!th_ins) {
            flb_errno();
            continue;
        }
        memset(th_ins, 0, sizeof(struct flb_out_thread_instance));

        th_ins->config = config;
        th_ins->ins = ins;
        th_ins->flush_id = 0;
        mk_list_init(&th_ins->flush_list);
        mk_list_init(&th_ins->flush_list_destroy);
        pthread_mutex_init(&th_ins->flush_mutex, NULL);
        mk_list_init(&th_ins->upstreams);

        upstream_thread_create(th_ins, ins);

        /* Create the event loop for this thread */
        evl = mk_event_loop_create(64);
        if (!evl) {
            flb_plg_error(ins, "could not create thread event loop");
            flb_free(th_ins);
            continue;
        }
        evl_bktq = flb_bucket_queue_create(FLB_ENGINE_PRIORITY_COUNT);
        if (!evl_bktq) {
            flb_plg_error(ins, "could not create thread event loop bucket queue");
            flb_free(evl);
            flb_free(th_ins);
            continue;
        }
        th_ins->evl = evl;
        th_ins->evl_bktq = evl_bktq;

        /*
         * Event loop setup between parent engine and this thread
         *
         *  - FLB engine uses 'ch_parent_events[1]' to dispatch tasks to this thread
         *  - Thread receive message on ch_parent_events[0]
         *
         * The mk_event_channel_create() will attach the pipe read end ch_parent_events[0]
         * to the local event loop 'evl'.
         */
        ret = mk_event_channel_create(th_ins->evl,
                                      &th_ins->ch_parent_events[0],
                                      &th_ins->ch_parent_events[1],
                                      th_ins);
        if (ret == -1) {
            flb_plg_error(th_ins->ins, "could not create thread channel");
            mk_event_loop_destroy(th_ins->evl);
            flb_bucket_queue_destroy(th_ins->evl_bktq);
            flb_free(th_ins);
            continue;
        }
        /* Signal type to indicate a "flush" request */
        th_ins->event.type = FLB_ENGINE_EV_THREAD_OUTPUT;
        th_ins->event.priority = FLB_ENGINE_PRIORITY_THREAD;

        if (i == 0) {
            ret = mk_event_channel_create(th_ins->evl,
                                        &th_ins->notification_channels[0],
                                        &th_ins->notification_channels[1],
                                        &th_ins->notification_event);
            if (ret == -1) {
                flb_plg_error(th_ins->ins, "could not create notification channel");

                mk_event_channel_destroy(th_ins->evl,
                                        th_ins->ch_parent_events[0],
                                        th_ins->ch_parent_events[1],
                                        th_ins);

                mk_event_loop_destroy(th_ins->evl);
                flb_bucket_queue_destroy(th_ins->evl_bktq);
                flb_free(th_ins);

                continue;
            }

            th_ins->notification_channels_initialized = FLB_TRUE;
            th_ins->notification_event.type = FLB_ENGINE_EV_NOTIFICATION;

            ins->notification_channel = th_ins->notification_channels[1];
        }

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

int flb_output_thread_pool_coros_size(struct flb_output_instance *ins)
{
    int n;
    int size = 0;
    struct mk_list *head;
    struct flb_tp *tp = ins->tp;
    struct flb_tp_thread *th;
    struct flb_out_thread_instance *th_ins;

    /* Signal each worker thread that needs to stop doing work */
    mk_list_foreach(head, &tp->list_threads) {
        th = mk_list_entry(head, struct flb_tp_thread, _head);
        if (th->status != FLB_THREAD_POOL_RUNNING) {
            continue;
        }

        th_ins = th->params.data;

        pthread_mutex_lock(&th_ins->flush_mutex);
        n = mk_list_size(&th_ins->flush_list);
        pthread_mutex_unlock(&th_ins->flush_mutex);

        size += n;
    }

    return size;
}

void flb_output_thread_pool_destroy(struct flb_output_instance *ins)
{
    int n;
    struct flb_task *stop = (struct flb_task *) 0xdeadbeef;
    struct flb_tp *tp = ins->tp;
    struct mk_list *head;
    struct flb_out_thread_instance *th_ins;
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
        n = flb_pipe_w(th_ins->ch_parent_events[1], &stop, sizeof(stop));
        if (n < 0) {
            flb_pipe_error();
            flb_plg_error(th_ins->ins, "could not signal worker thread");
            flb_free(th_ins);
            continue;
        }
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
