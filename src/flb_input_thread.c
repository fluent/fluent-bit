/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input_thread.h>
#include <fluent-bit/flb_notification.h>

static int input_thread_instance_set_status(struct flb_input_instance *ins, uint32_t status);
static int input_thread_instance_get_status(struct flb_input_instance *ins);

/* Cleanup function that runs every 1.5 second */
static void cb_thread_sched_timer(struct flb_config *ctx, void *data)
{
    struct flb_input_instance *ins;

    (void) ctx;

    /* Downstream timeout handling */
    ins = (struct flb_input_instance *) data;

    flb_upstream_conn_timeouts(&ins->upstreams);
    flb_downstream_conn_timeouts(&ins->downstreams);
}

static inline int handle_input_event(flb_pipefd_t fd, struct flb_input_instance *ins)
{
    int bytes;
    int ins_id;
    uint32_t type;
    uint32_t operation;
    uint64_t val;
    struct flb_config *config = ins->config;

    bytes = read(fd, &val, sizeof(val));
    if (bytes == -1) {
        flb_errno();
        return -1;
    }

    type   = FLB_BITS_U64_HIGH(val);
    operation = FLB_BITS_U64_LOW(val);

    /* At the moment we only support events coming from an input coroutine */
    if (type == FLB_ENGINE_IN_CORO) {
        ins_id = ins->id;
        flb_input_coro_finished(config, ins_id);
    }
    else if (type == FLB_INPUT_THREAD_TO_THREAD) {
        if (operation == FLB_INPUT_THREAD_PAUSE) {
            if (ins->p->cb_pause && ins->context) {
                ins->p->cb_pause(ins->context, ins->config);
            }
        }
        else if (operation == FLB_INPUT_THREAD_RESUME) {
            if (ins->p->cb_resume) {
                ins->p->cb_resume(ins->context, ins->config);
            }
        }
        else if (operation == FLB_INPUT_THREAD_EXIT) {
            return FLB_INPUT_THREAD_EXIT;
        }
    }
    else {
        flb_error("[thread event loop] it happends on fd=%i, invalid type=%i", fd, type);
        return -1;
    }

    return 0;
}

static inline int handle_input_thread_event(flb_pipefd_t fd, struct flb_config *config)
{
    int bytes;
    uint32_t type;
    uint32_t ins_id;
    uint64_t val;

    bytes = flb_pipe_r(fd, &val, sizeof(val));
    if (bytes == -1) {
        flb_errno();
        return -1;
    }

    /* Get type and key */
    type   = FLB_BITS_U64_HIGH(val);
    ins_id = FLB_BITS_U64_LOW(val);

    /* At the moment we only support events coming from an input coroutine */
    if (type == FLB_ENGINE_IN_CORO) {
        flb_input_coro_finished(config, ins_id);
    }
    else {
        flb_error("[thread event loop] invalid thread event type %i for input handler",
                  type);
        return -1;
    }

    return 0;
}

static int input_collector_fd(flb_pipefd_t fd, struct flb_input_instance *ins)
{
    struct mk_list *head;
    struct flb_input_collector *collector = NULL;
    struct flb_input_coro *input_coro;
    struct flb_config *config = ins->config;

    mk_list_foreach(head, &ins->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        if (collector->fd_event == fd) {
            break;
        }
        else if (collector->fd_timer == fd) {
            flb_utils_timer_consume(fd);
            break;
        }
        collector = NULL;
    }

    /* No matches */
    if (!collector) {
        return -1;
    }

    if (collector->running == FLB_FALSE) {
        return -1;
    }

    /* Trigger the collector callback */
    if (collector->instance->runs_in_coroutine) {
        input_coro = flb_input_coro_collect(collector, config);
        if (!input_coro) {
            return -1;
        }
        flb_input_coro_resume(input_coro);
    }
    else {
        collector->cb_collect(collector->instance, config,
                              collector->instance->context);
    }

    return 0;
}

static FLB_INLINE int engine_handle_event(flb_pipefd_t fd, int mask,
                                          struct flb_input_instance *ins,
                                          struct flb_config *config)
{
    int ret;

    if (mask & MK_EVENT_READ) {
        /* Try to match the file descriptor with a collector event */
        ret = input_collector_fd(fd, ins);
        if (ret != -1) {
            return ret;
        }
    }

    return 0;
}

static void input_thread_instance_destroy(struct flb_input_thread_instance *thi)
{
    if (thi->notification_channels_initialized == FLB_TRUE) {
        mk_event_channel_destroy(thi->evl,
                                 thi->notification_channels[0],
                                 thi->notification_channels[1],
                                 &thi->notification_event);

        thi->notification_channels_initialized = FLB_FALSE;
    }

    if (thi->evl) {
        mk_event_loop_destroy(thi->evl);
    }

    /* ch_parent_events */
    if (thi->ch_parent_events[0] > 0) {
        mk_event_closesocket(thi->ch_parent_events[0]);
    }
    if (thi->ch_parent_events[1] > 0) {
        mk_event_closesocket(thi->ch_parent_events[1]);
    }

    /* ch_thread_events */
    if (thi->ch_thread_events[0] > 0) {
        mk_event_closesocket(thi->ch_thread_events[0]);
    }
    if (thi->ch_thread_events[1] > 0) {
        mk_event_closesocket(thi->ch_thread_events[1]);
    }

    flb_tp_destroy(thi->tp);
    flb_free(thi);
}

static struct flb_input_thread_instance *input_thread_instance_create(struct flb_input_instance *ins)
{
    int ret;
    struct flb_input_thread_instance *thi;

    /* context for thread */
    thi = flb_calloc(1, sizeof(struct flb_input_thread_instance));
    if (!thi) {
        flb_errno();
        return NULL;
    }
    thi->ins = ins;
    thi->config = ins->config;

    /* init status */
    thi->init_status = 0;
    pthread_mutex_init(&thi->init_mutex, NULL);

    /* init condition */
    pthread_cond_init(&thi->init_condition, NULL);

    /* initialize lists */
    mk_list_init(&thi->input_coro_list);
    mk_list_init(&thi->input_coro_list_destroy);

    /* event loop */
    thi->evl = mk_event_loop_create(256);
    if (!thi->evl) {
        input_thread_instance_destroy(thi);
        return NULL;
    }

    /* channel to receive parent (engine) notifications */
    ret = mk_event_channel_create(thi->evl,
                                  &thi->ch_parent_events[0],
                                  &thi->ch_parent_events[1],
                                  &thi->event);
    if (ret == -1) {
        flb_error("could not initialize parent channels for %s",
                  flb_input_name(ins));
        input_thread_instance_destroy(thi);
        return NULL;
    }
    thi->event.type = FLB_ENGINE_EV_INPUT;

    /* channel to send messages to local event loop */
    ret = mk_event_channel_create(thi->evl,
                                  &thi->ch_thread_events[0],
                                  &thi->ch_thread_events[1],
                                  &thi->event_local);
    if (ret == -1) {
        flb_error("could not initialize parent channels for %s",
                  flb_input_name(ins));
        input_thread_instance_destroy(thi);
        return NULL;
    }
    thi->event_local.type = FLB_ENGINE_EV_THREAD_INPUT;

    ret = mk_event_channel_create(thi->evl,
                                  &thi->notification_channels[0],
                                  &thi->notification_channels[1],
                                  &thi->notification_event);
    if (ret == -1) {
        flb_error("could not create notification channel for %s",
                  flb_input_name(ins));

        input_thread_instance_destroy(thi);

        return NULL;
    }

    thi->notification_channels_initialized = FLB_TRUE;
    thi->notification_event.type = FLB_ENGINE_EV_NOTIFICATION;

    ins->notification_channel = thi->notification_channels[1];

    /* create thread pool, just one worker */
    thi->tp = flb_tp_create(ins->config);
    if (!thi->tp) {
        flb_error("could not create thread pool on input instance '%s'",
                  flb_input_name(ins));
        input_thread_instance_destroy(thi);
        return NULL;
    }

    return thi;
}


static void input_thread(void *data)
{
    int ret;
    int thread_id;
    char tmp[64];
    int instance_exit = FLB_FALSE;
    struct mk_event *event;
    struct flb_input_instance *ins;
    struct flb_bucket_queue *evl_bktq = NULL;
    struct flb_input_thread_instance *thi;
    struct flb_input_plugin *p;
    struct flb_sched *sched = NULL;
    struct flb_net_dns dns_ctx = {0};
    struct flb_notification *notification;

    thi = (struct flb_input_thread_instance *) data;
    ins = thi->ins;
    p = ins->p;

    flb_engine_evl_set(thi->evl);

    /* Create a scheduler context */
    sched = flb_sched_create(ins->config, thi->evl);
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
        flb_error("could not schedule input thread permanent callback");
        return;
    }

    flb_coro_thread_init();

    flb_net_ctx_init(&dns_ctx);
    flb_net_dns_ctx_set(&dns_ctx);

    thread_id = thi->th->id;
    snprintf(tmp, sizeof(tmp) - 1, "flb-in-%s-w%i", ins->name, thread_id);
    mk_utils_worker_rename(tmp);

    /* invoke plugin 'init' callback */
    ret = p->cb_init(ins, ins->config, ins->data);
    if (ret == -1) {
        flb_error("failed initialize input %s", flb_input_name(ins));
        /* message the parent thread that this thread could not be initialized */
        input_thread_instance_set_status(ins, FLB_INPUT_THREAD_ERROR);
        return;
    }

    ins->processor->notification_channel = ins->notification_channel;

    ret = flb_processor_init(ins->processor);
    if (ret == -1) {
        flb_error("failed initialize processors for input %s",
                  flb_input_name(ins));
        input_thread_instance_set_status(ins, FLB_INPUT_THREAD_ERROR);
        return;
    }

    flb_plg_debug(ins, "[thread init] initialization OK");
    input_thread_instance_set_status(ins, FLB_INPUT_THREAD_OK);

    /*
     * Wait for parent thread to signal this thread so we can start collectors and
     * get into the event loop
     */
    ret = flb_input_thread_collectors_signal_wait(ins);
    if (ret == -1) {
        flb_error("could not retrieve collectors signal from parent thread on '%s'",
                  flb_input_name(ins));
        return;
    }

    /* event loop queue */
    evl_bktq = flb_bucket_queue_create(FLB_ENGINE_PRIORITY_COUNT);

    /* Start collectors */
    flb_input_thread_collectors_start(ins);

    /* If the plugin contains a 'pre_run' callback, invoke it */
    if (p->cb_pre_run) {
        ret = p->cb_pre_run(ins, ins->config, ins->context);
        if (ret == -1) {
            /*
             * FIXME: how do we report a failed pre-run status to the parent thread ?,
             * as of know it does not seems to be necessary since the only plugins
             * using that callback are tail and systemd, but those are just writing a
             * byte to a recently created pipe in the initialization.
             */
        }
    }

    while (1) {
        mk_event_wait(thi->evl);
        flb_event_priority_live_foreach(event, evl_bktq, thi->evl, FLB_ENGINE_LOOP_MAX_ITER) {
            if (event->type == FLB_ENGINE_EV_CORE) {
                ret = engine_handle_event(event->fd, event->mask,
                                          ins, thi->config);
                if (ret == FLB_ENGINE_STOP) {
                    continue;
                }
                else if (ret == FLB_ENGINE_SHUTDOWN) {
                    continue;
                }
            }
            else if (event->type & FLB_ENGINE_EV_SCHED) {
                /* Event type registered by the Scheduler */
                flb_sched_event_handler(ins->config, event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD_ENGINE) {
                struct flb_output_flush *output_flush;

                /* Read the coroutine reference */
                ret = flb_pipe_r(event->fd, &output_flush, sizeof(struct flb_output_flush *));
                if (ret <= 0 || output_flush == 0) {
                    flb_errno();
                    continue;
                }

                /* Init coroutine */
                flb_coro_resume(output_flush->coro);
            }
            else if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD) {
                struct flb_connection *connection;

                /*
                 * Check if we have some co-routine associated to this event,
                 * if so, resume the co-routine
                 */
                connection = (struct flb_connection *) event;

                if (connection->coroutine != NULL) {
                    flb_trace("[engine] resuming coroutine=%p",
                              connection->coroutine);

                    flb_coro_resume(connection->coroutine);
                }
            }
            else if (event->type == FLB_ENGINE_EV_INPUT) {
                ret = handle_input_event(event->fd, ins);
                if (ret == FLB_INPUT_THREAD_EXIT) {
                    instance_exit = FLB_TRUE;
                }
            }
            else if (event->type == FLB_ENGINE_EV_THREAD_INPUT) {
                handle_input_thread_event(event->fd, ins->config);
            }
            else if(event->type == FLB_ENGINE_EV_NOTIFICATION) {
                ret = flb_notification_receive(event->fd, &notification);

                if (ret == 0) {
                    ret = flb_notification_deliver(notification);

                    flb_notification_cleanup(notification);
                }
            }
        }

        flb_net_dns_lookup_context_cleanup(&dns_ctx);

        /* Destroy upstream connections from the 'pending destroy list' */
        flb_upstream_conn_pending_destroy_list(&ins->upstreams);

        /* Destroy downstream connections from the 'pending destroy list' */
        flb_downstream_conn_pending_destroy_list(&ins->downstreams);
        flb_sched_timer_cleanup(sched);

        /* Check if the instance must exit */
        if (instance_exit) {
            /* Invoke exit callback */
            if (ins->p->cb_exit && ins->context) {
                ins->p->cb_exit(ins->context, ins->config);
            }

            /* break the loop */
            break;
        }
    }

    /* Create the bucket queue (FLB_ENGINE_PRIORITY_COUNT priorities) */
    flb_bucket_queue_destroy(evl_bktq);
    flb_sched_destroy(sched);
    input_thread_instance_destroy(thi);
}


/*
 * Signal the thread event loop to pause the running plugin instance. This function
 * must be called only from the main thread/pipeline.
 */
int flb_input_thread_instance_pause(struct flb_input_instance *ins)
{
    int ret;
    uint64_t val;
    struct flb_input_thread_instance *thi = ins->thi;

    if (thi == NULL) {
        return 0;
    }

    flb_plg_debug(ins, "thread pause instance");

    /* compose message to pause the thread */
    val = FLB_BITS_U64_SET(FLB_INPUT_THREAD_TO_THREAD,
                           FLB_INPUT_THREAD_PAUSE);

    ret = flb_pipe_w(thi->ch_parent_events[1], &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    return 0;
}

/*
 * Signal the thread event loop to resume the running plugin instance. This function
 * must be called only from the main thread/pipeline.
 */
int flb_input_thread_instance_resume(struct flb_input_instance *ins)
{
    int ret;
    uint64_t val;
    struct flb_input_thread_instance *thi = ins->thi;

    if (thi == NULL) {
        return 0;
    }

    flb_plg_debug(ins, "thread resume instance");

    /* compose message to resume the thread */
    val = FLB_BITS_U64_SET(FLB_INPUT_THREAD_TO_THREAD,
                           FLB_INPUT_THREAD_RESUME);

    ret = flb_pipe_w(thi->ch_parent_events[1], &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    return 0;
}

int flb_input_thread_instance_exit(struct flb_input_instance *ins)
{
    int ret;
    uint64_t val;
    struct flb_input_thread_instance *thi = ins->thi;
    pthread_t tid;

    if (thi == NULL) {
        return 0;
    }

    memcpy(&tid, &thi->th->tid, sizeof(pthread_t));

    /* compose message to pause the thread */
    val = FLB_BITS_U64_SET(FLB_INPUT_THREAD_TO_THREAD,
                           FLB_INPUT_THREAD_EXIT);

    ret = flb_pipe_w(thi->ch_parent_events[1], &val, sizeof(val));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    pthread_join(tid, NULL);
    flb_plg_debug(ins, "thread exit instance");

    return 0;
}


/* Initialize a plugin under a threaded context */
int flb_input_thread_instance_init(struct flb_config *config, struct flb_input_instance *ins)
{
    int ret;
    struct flb_tp_thread *th;
    struct flb_input_thread_instance *thi;

    /* Create the threaded context for the instance in question */
    thi = input_thread_instance_create(ins);
    if (!thi) {
        return -1;
    }
    ins->thi = thi;

    /* Spawn the thread */
    th = flb_tp_thread_create(thi->tp, input_thread, thi, config);
    if (!th) {
        flb_plg_error(ins, "could not register worker thread");
        input_thread_instance_destroy(thi);
        return -1;
    }
    thi->th = th;

    /* start the thread */
    ret = flb_tp_thread_start(thi->tp, thi->th);
    if (ret != 0) {
        return -1;
    }

    ret = input_thread_instance_get_status(ins);
    if (ret == -1) {
        flb_plg_error(ins, "unexpected error loading plugin instance");
    }
    else if (ret == FLB_FALSE) {
        flb_plg_error(ins, "could not initialize threaded plugin instance");
    }
    else if (ret == FLB_TRUE) {
        flb_plg_info(ins, "thread instance initialized");
    }

    return 0;
}

int flb_input_thread_instance_pre_run(struct flb_config *config, struct flb_input_instance *ins)
{
    int ret;

    if (ins->p->cb_pre_run) {
        /*
         * the pre_run callback is invoked automatically from the instance thread. we just need to check for the
         * final status.
         */
        ret = input_thread_instance_get_status(ins);
        if (ret == -1) {
            return -1;
        }
        else if (ret == FLB_FALSE) {
            return -1;
        }
        else if (ret == FLB_TRUE) {
            return 0;
        }
    }

    return 0;
}

static int input_thread_instance_set_status(struct flb_input_instance *ins, uint32_t status)
{
    struct flb_input_thread_instance *thi;

    thi = ins->thi;

    pthread_mutex_lock(&thi->init_mutex);

    thi->init_status = status;

    pthread_cond_signal(&thi->init_condition);
    pthread_mutex_unlock(&thi->init_mutex);

    return 0;
}

static int input_thread_instance_get_status(struct flb_input_instance *ins)
{

    uint32_t status;
    struct flb_input_thread_instance *thi;

    thi = ins->thi;

    /* Wait for thread to report a status */
    pthread_mutex_lock(&thi->init_mutex);
    while (thi->init_status == 0) {
        pthread_cond_wait(&thi->init_condition, &thi->init_mutex);
    }
    pthread_mutex_unlock(&thi->init_mutex);

    /* re-initialize condition */
    pthread_cond_destroy(&thi->init_condition);
    pthread_cond_init(&thi->init_condition, NULL);

    /* get the final status */
    status = thi->init_status;
    if (status == FLB_INPUT_THREAD_OK) {
        return FLB_TRUE;
    }
    else if (status == FLB_INPUT_THREAD_ERROR) {
        return FLB_FALSE;;
    }

    return -1;
}

/* Wait for an input thread instance to become ready, or a failure status */
int flb_input_thread_wait_until_is_ready(struct flb_input_instance *ins)
{
    uint64_t status = 0;
    size_t bytes;
    struct flb_input_thread_instance *thi;

    thi = ins->thi;

    bytes = read(thi->ch_parent_events[0], &status, sizeof(uint64_t));
    if (bytes <= 0) {
        flb_errno();
        return -1;
    }

    if (status == 0) {
        return -1;
    }

    return FLB_TRUE;
}


/*
 * Invoked from the main 'input' interface to signal the threaded plugin instance so
 * it can start the collectors.
 */
int flb_input_thread_collectors_signal_start(struct flb_input_instance *ins)
{
    int ret;
    uint64_t val;
    struct flb_input_thread_instance *thi;

    thi = ins->thi;

    /* compose message */
    val = FLB_BITS_U64_SET(FLB_INPUT_THREAD_TO_THREAD,
                           FLB_INPUT_THREAD_START_COLLECTORS);

    ret = flb_pipe_w(thi->ch_parent_events[1], &val, sizeof(uint64_t));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    return 0;
}

int flb_input_thread_collectors_signal_wait(struct flb_input_instance *ins)
{
    size_t bytes;
    uint32_t type;
    uint32_t op;
    uint64_t val = 0;
    struct flb_input_thread_instance *thi;

    thi = ins->thi;
    bytes = flb_pipe_r(thi->ch_parent_events[0], &val, sizeof(uint64_t));
    if (bytes <= 0) {
        flb_errno();
        return -1;
    }

    /* Get type and status */
    type  = FLB_BITS_U64_HIGH(val);
    op    = FLB_BITS_U64_LOW(val);

    if (type != FLB_INPUT_THREAD_TO_THREAD || op != FLB_INPUT_THREAD_START_COLLECTORS) {
        flb_plg_error(ins, "wrong event, type=%i op=%i\n", type, op); fflush(stdout);
        return -1;
    }

    return 0;
}

int flb_input_thread_collectors_start(struct flb_input_instance *ins)
{
    int ret;
    struct mk_list *head;
    struct flb_input_collector *coll;

    mk_list_foreach(head, &ins->collectors) {
        coll = mk_list_entry(head, struct flb_input_collector, _head);
        ret = flb_input_collector_start(coll->id, ins);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}
