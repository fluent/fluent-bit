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

#include <stdio.h>
#include <stdlib.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_bits.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_engine_dispatch.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_sosreport.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_http_server.h>

#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics_exporter.h>
#endif

#ifdef FLB_HAVE_STREAM_PROCESSOR
#include <fluent-bit/stream_processor/flb_sp.h>
#endif

int flb_engine_destroy_tasks(struct mk_list *tasks)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_task *task;

    mk_list_foreach_safe(head, tmp, tasks) {
        task = mk_list_entry(head, struct flb_task, _head);
        flb_task_destroy(task, FLB_FALSE);
        c++;
    }

    return c;
}

int flb_engine_flush(struct flb_config *config,
                     struct flb_input_plugin *in_force)
{
    struct flb_input_instance *in;
    struct flb_input_plugin *p;
    struct mk_list *head;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        p = in->p;

        if (in_force != NULL && p != in_force) {
            continue;
        }
        flb_engine_dispatch(0, in, config);
    }

    return 0;
}

static inline int flb_engine_manager(flb_pipefd_t fd, struct flb_config *config)
{
    int ret;
    int bytes;
    int task_id;
    int thread_id;
    int retries;
    int retry_seconds;
    uint32_t type;
    uint32_t key;
    uint64_t val;
    struct flb_task *task;
    struct flb_task_retry *retry;
    struct flb_output_thread *out_th;
    struct flb_output_instance *ins;

    bytes = flb_pipe_r(fd, &val, sizeof(val));
    if (bytes == -1) {
        flb_errno();
        return -1;
    }

    /* Get type and key */
    type = FLB_BITS_U64_HIGH(val);
    key  = FLB_BITS_U64_LOW(val);

    /* Flush all remaining data */
    if (type == 1) {                  /* Engine type */
        if (key == FLB_ENGINE_STOP) {
            flb_trace("[engine] flush enqueued data");
            flb_engine_flush(config, NULL);
            return FLB_ENGINE_STOP;
        }
    }
    else if (type == FLB_ENGINE_IN_THREAD) {
        /* Event coming from an input thread */
        flb_input_thread_destroy_id(key, config);
    }
    else if (type == FLB_ENGINE_TASK) {
        /*
         * The notion of ENGINE_TASK is associated to outputs. All thread
         * references below belongs to flb_output_thread's.
         */
        ret       = FLB_TASK_RET(key);
        task_id   = FLB_TASK_ID(key);
        thread_id = FLB_TASK_TH(key);

#ifdef FLB_HAVE_TRACE
        char *trace_st = NULL;

        if (ret == FLB_OK) {
            trace_st = "OK";
        }
        else if (ret == FLB_ERROR) {
            trace_st = "ERROR";
        }
        else if (ret == FLB_RETRY) {
            trace_st = "RETRY";
        }

        flb_trace("%s[engine] [task event]%s task_id=%i thread_id=%i return=%s",
                  ANSI_YELLOW, ANSI_RESET,
                  task_id, thread_id, trace_st);
#endif

        task   = config->tasks_map[task_id].task;
        out_th = flb_output_thread_get(thread_id, task);
        ins    = out_th->o_ins;

        /* A thread has finished, delete it */
        if (ret == FLB_OK) {
            /* Inform the user if a 'retry' succedeed */
            if (mk_list_size(&task->retries) > 0) {
                retries = flb_task_retry_count(task, out_th->parent);
                if (retries > 0) {
                    flb_info("[engine] flush chunk '%s' succeeded at retry %i: "
                             "task_id=%i, input=%s > output=%s",
                             flb_input_chunk_get_name(task->ic),
                             retries, out_th->id,
                             flb_input_name(task->i_ins),
                             flb_output_name(ins));
                }
            }
            else if (flb_task_from_fs_storage(task) == FLB_TRUE) {
                flb_info("[engine] flush backlog chunk '%s' succeeded: "
                         "task_id=%i, input=%s > output=%s",
                         flb_input_chunk_get_name(task->ic),
                         out_th->id,
                         flb_input_name(task->i_ins),
                         flb_output_name(ins));
            }
            flb_task_retry_clean(task, out_th->parent);
            flb_output_thread_destroy_id(thread_id, task);
            if (task->users == 0 && mk_list_size(&task->retries) == 0) {
                flb_task_destroy(task, FLB_TRUE);
            }
        }
        else if (ret == FLB_RETRY) {
            /* Create a Task-Retry */
            retry = flb_task_retry_create(task, out_th);
            if (!retry) {
                /*
                 * It can fail in two situations:
                 *
                 * - No enough memory (unlikely)
                 * - It reached the maximum number of re-tries
                 */
#ifdef FLB_HAVE_METRICS
                flb_metrics_sum(FLB_METRIC_OUT_RETRY_FAILED, 1,
                                out_th->o_ins->metrics);
#endif
                /* Notify about this failed retry */
                flb_warn("[engine] chunk '%s' cannot be retried: "
                         "task_id=%i, input=%s > output=%s",
                         flb_input_chunk_get_name(task->ic),
                         task_id,
                         flb_input_name(task->i_ins),
                         flb_output_name(ins));

                flb_output_thread_destroy_id(thread_id, task);
                if (task->users == 0 && mk_list_size(&task->retries) == 0) {
                    flb_task_destroy(task, FLB_TRUE);
                }

                return 0;
            }

#ifdef FLB_HAVE_METRICS
            flb_metrics_sum(FLB_METRIC_OUT_RETRY, 1, out_th->o_ins->metrics);
#endif

            /* Always destroy the old thread */
            flb_output_thread_destroy_id(thread_id, task);

            /* Let the scheduler to retry the failed task/thread */
            retry_seconds = flb_sched_request_create(config,
                                                     retry, retry->attemps);

            /*
             * If for some reason the Scheduler could not include this retry,
             * we need to get rid of it, likely this is because of not enough
             * memory available or we ran out of file descriptors.
             */
            if (retry_seconds == -1) {
                flb_warn("[engine] retry for chunk '%s' could not be scheduled: "
                         "input=%s > output=%s",
                         flb_input_chunk_get_name(task->ic),
                         flb_input_name(task->i_ins),
                         flb_output_name(ins));

                flb_task_retry_destroy(retry);
                if (task->users == 0 && mk_list_size(&task->retries) == 0) {
                    flb_task_destroy(task, FLB_TRUE);
                }
            }
            else {
                /* Inform the user 'retry' has been scheduled */
                flb_warn("[engine] failed to flush chunk '%s', retry in %i seconds: "
                         "task_id=%i, input=%s > output=%s",
                         flb_input_chunk_get_name(task->ic),
                         retry_seconds,
                         task->id,
                         flb_input_name(task->i_ins),
                         flb_output_name(ins));
            }
        }
        else if (ret == FLB_ERROR) {
            flb_output_thread_destroy_id(thread_id, task);
            if (task->users == 0 && mk_list_size(&task->retries) == 0) {
                flb_task_destroy(task, FLB_TRUE);
            }
        }
    }

    return 0;
}

static FLB_INLINE int flb_engine_handle_event(flb_pipefd_t fd, int mask,
                                              struct flb_config *config)
{
    int ret;

    /* flb_engine_shutdown was already initiated */
    if (config->is_running == FLB_FALSE) {
        return 0;
    }

    if (mask & MK_EVENT_READ) {
        /* Check if we need to flush */
        if (config->flush_fd == fd) {
            flb_utils_timer_consume(fd);
            flb_engine_flush(config, NULL);
            return 0;
        }
        else if (config->shutdown_fd == fd) {
            flb_utils_pipe_byte_consume(fd);
            return FLB_ENGINE_SHUTDOWN;
        }
        else if (config->ch_manager[0] == fd) {
            ret = flb_engine_manager(fd, config);
            if (ret == FLB_ENGINE_STOP) {
                return FLB_ENGINE_STOP;
            }
        }

        /* Try to match the file descriptor with a collector event */
        ret = flb_input_collector_fd(fd, config);
        if (ret != -1) {
            return ret;
        }

        /* Metrics exporter event ? */
#ifdef FLB_HAVE_METRICS
        ret = flb_me_fd_event(fd, config->metrics);
        if (ret != -1) {
            return ret;
        }
#endif

#ifdef FLB_HAVE_STREAM_PROCESSOR
        if (config->stream_processor_ctx) {
            ret = flb_sp_fd_event(fd, config->stream_processor_ctx);
            if (ret != -1) {
                return ret;
            }
        }
#endif
    }

    return 0;
}

static int flb_engine_started(struct flb_config *config)
{
    uint64_t val;

    /* Check the channel is valid (enabled by library mode) */
    if (config->ch_notif[1] <= 0) {
        return -1;
    }

    val = FLB_ENGINE_STARTED;
    return flb_pipe_w(config->ch_notif[1], &val, sizeof(uint64_t));
}

int flb_engine_failed(struct flb_config *config)
{
    int ret;
    uint64_t val;

    /* Check the channel is valid (enabled by library mode) */
    if (config->ch_notif[1] <= 0) {
        return -1;
    }

    val = FLB_ENGINE_FAILED;
    ret = flb_pipe_w(config->ch_notif[1], &val, sizeof(uint64_t));
    if (ret == -1) {
        flb_error("[engine] fail to dispatch FAILED message");
    }

    return ret;
}

static int flb_engine_log_start(struct flb_config *config)
{
    int type;
    int level;

    /* Log Level */
    if (config->verbose != FLB_LOG_INFO) {
        level = config->verbose;
    }
    else {
        level = FLB_LOG_INFO;
    }

    /* Destination based on type */
    if (config->log_file) {
        type = FLB_LOG_FILE;
    }
    else {
        type = FLB_LOG_STDERR;
    }

    if (flb_log_init(config, type, level, config->log_file) == NULL) {
        return -1;
    }

    return 0;
}

int flb_engine_start(struct flb_config *config)
{
    int ret;
    char tmp[16];
    struct flb_time t_flush;
    struct mk_event *event;
    struct mk_event_loop *evl;

    /* HTTP Server */
#ifdef FLB_HAVE_HTTP
    if (config->http_server == FLB_TRUE) {
        flb_http_server_start(config);
    }
#endif

    /* Start the Logging service */
    ret = flb_engine_log_start(config);
    if (ret == -1) {
        return -1;
    }

    /* Start the Storage engine */
    ret = flb_storage_create(config);
    if (ret == -1) {
        return -1;
    }

    flb_info("[engine] started (pid=%i)", getpid());

    /* Debug coroutine stack size */
    flb_utils_bytes_to_human_readable_size(config->coro_stack_size,
                                           tmp, sizeof(tmp));
    flb_debug("[engine] coroutine stack size: %u bytes (%s)",
              config->coro_stack_size, tmp);

    /* Create the event loop and set it in the global configuration */
    evl = mk_event_loop_create(256);
    if (!evl) {
        return -1;
    }
    config->evl = evl;

    /*
     * Create a communication channel: this routine creates a channel to
     * signal the Engine event loop. It's useful to stop the event loop
     * or to instruct anything else without break.
     */
    ret = mk_event_channel_create(config->evl,
                                  &config->ch_manager[0],
                                  &config->ch_manager[1],
                                  config);
    if (ret != 0) {
        flb_error("[engine] could not create manager channels");
        return -1;
    }

    /* Initialize input plugins */
    ret = flb_input_init_all(config);
    if (ret == -1) {
        return -1;
    }

    /* Initialize filter plugins */
    ret = flb_filter_init_all(config);
    if (ret == -1) {
        return -1;
    }

    /* Inputs pre-run */
    flb_input_pre_run_all(config);

    /* Initialize output plugins */
    ret = flb_output_init_all(config);
    if (ret == -1 && config->support_mode == FLB_FALSE) {
        return -1;
    }

    /* Outputs pre-run */
    flb_output_pre_run(config);

    /* Create and register the timer fd for flush procedure */
    event = &config->event_flush;
    event->mask = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    flb_time_from_double(&t_flush, config->flush);
    config->flush_fd = mk_event_timeout_create(evl,
                                               t_flush.tm.tv_sec,
                                               t_flush.tm.tv_nsec,
                                               event);
    if (config->flush_fd == -1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH_CREATE);
    }

    /* Initialize the scheduler */
    ret = flb_sched_init(config);
    if (ret == -1) {
        flb_error("[engine] scheduler could not start");
        return -1;
    }

    /* Initialize collectors */
    flb_input_collectors_start(config);

    /* Prepare routing paths */
    ret = flb_router_io_set(config);
    if (ret == -1) {
        flb_error("[engine] router failed");
        return -1;
    }

    /* Support mode only */
    if (config->support_mode == FLB_TRUE) {
        sleep(1);
        flb_sosreport(config);
        exit(1);
    }

    /* Initialize Metrics exporter */
#ifdef FLB_HAVE_METRICS
    config->metrics = flb_me_create(config);
#endif

    /* Initialize HTTP Server */
#ifdef FLB_HAVE_HTTP_SERVER
    if (config->http_server == FLB_TRUE) {
        config->http_ctx = flb_hs_create(config->http_listen, config->http_port,
                                         config);
        flb_hs_start(config->http_ctx);
    }
#endif

#ifdef FLB_HAVE_STREAM_PROCESSOR
    config->stream_processor_ctx = flb_sp_create(config);
    if (!config->stream_processor_ctx) {
        flb_error("[engine] could not initialize stream processor");
    }
#endif

    /* Signal that we have started */
    flb_engine_started(config);

    while (1) {
        mk_event_wait(evl);
        mk_event_foreach(event, evl) {
            if (event->type == FLB_ENGINE_EV_CORE) {
                ret = flb_engine_handle_event(event->fd, event->mask, config);
                if (ret == FLB_ENGINE_STOP) {
                    /*
                     * We are preparing to shutdown, we give a graceful time
                     * of 'config->grace' seconds to process any pending event.
                     */
                    event = &config->event_shutdown;
                    event->mask = MK_EVENT_EMPTY;
                    event->status = MK_EVENT_NONE;
                    config->shutdown_fd = mk_event_timeout_create(evl, config->grace, 0, event);
                    flb_warn("[engine] service will stop in %u seconds", config->grace);
                }
                else if (ret == FLB_ENGINE_SHUTDOWN) {
                    flb_info("[engine] service stopped");
                    if (config->shutdown_fd > 0) {
                        mk_event_timeout_destroy(config->evl,
                                                 &config->event_shutdown);
                    }

                    /*
                     * Grace period has finished, but we need to check if there is
                     * any pending running task. A running task is associated to an
                     * output co-routine, since we don't know what's the state or
                     * resources allocated by that co-routine, the best thing is to
                     * wait again for the grace period and re-check again.
                     */
                    ret = flb_task_running_count(config);
                    if (ret > 0) {
                        flb_warn("[engine] shutdown delayed, grace period has "
                                 "finished but some tasks are still running.");
                        flb_task_running_print(config);
                        flb_engine_exit(config);
                    }
                    else {
                        ret = config->exit_status_code;
                        flb_engine_shutdown(config);
                        config = NULL;
                        return ret;
                    }
                }
            }
            else if (event->type & FLB_ENGINE_EV_SCHED) {
                /* Event type registered by the Scheduler */
                flb_sched_event_handler(config, event);
            }
            else if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD) {
                struct flb_upstream_conn *u_conn;
                struct flb_thread *th;

                /*
                 * Check if we have some co-routine associated to this event,
                 * if so, resume the co-routine
                 */
                u_conn = (struct flb_upstream_conn *) event;
                th = u_conn->thread;
                flb_trace("[engine] resuming thread=%p", th);
                flb_thread_resume(th);
            }
        }

        /* Cleanup functions associated to events and timers */
        if (config->is_running == FLB_TRUE) {
            flb_sched_timer_cleanup(config->sched);
            flb_upstream_conn_timeouts(config);
        }
    }
}

/* Release all resources associated to the engine */
int flb_engine_shutdown(struct flb_config *config)
{

    config->is_running = FLB_FALSE;
    flb_input_pause_all(config);

#ifdef FLB_HAVE_STREAM_PROCESSOR
    if (config->stream_processor_ctx) {
        flb_sp_destroy(config->stream_processor_ctx);
    }
#endif

    /* router */
    flb_router_exit(config);

#ifdef FLB_HAVE_PARSER
    /* parsers */
    flb_parser_exit(config);
#endif

    /* cleanup plugins */
    flb_filter_exit(config);
    flb_input_exit_all(config);
    flb_output_exit(config);


    /* Destroy the storage context */
    flb_storage_destroy(config);

    /* metrics */
#ifdef FLB_HAVE_METRICS
    if (config->metrics) {
        flb_me_destroy(config->metrics);
    }
#endif

#ifdef FLB_HAVE_HTTP_SERVER
    if (config->http_server == FLB_TRUE) {
        flb_hs_destroy(config->http_ctx);
    }
#endif

    flb_config_exit(config);

    return 0;
}

int flb_engine_exit(struct flb_config *config)
{
    int ret;
    uint64_t val = FLB_ENGINE_EV_STOP;

    flb_input_pause_all(config);

    val = FLB_ENGINE_EV_STOP;
    ret = flb_pipe_w(config->ch_manager[1], &val, sizeof(uint64_t));
    return ret;
}

int flb_engine_exit_status(struct flb_config *config, int status)
{
    config->exit_status_code = status;
    return flb_engine_exit(config);
}
