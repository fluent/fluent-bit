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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_bucket_queue.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_bits.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_custom.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_engine_dispatch.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_sosreport.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_ring_buffer.h>
#include <fluent-bit/flb_notification.h>
#include <fluent-bit/flb_simd.h>

#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics_exporter.h>
#endif

#ifdef FLB_HAVE_STREAM_PROCESSOR
#include <fluent-bit/stream_processor/flb_sp.h>
#endif

#ifdef FLB_HAVE_AWS_ERROR_REPORTER
#include <fluent-bit/aws/flb_aws_error_reporter.h>

extern struct flb_aws_error_reporter *error_reporter;
#endif

#include <ctraces/ctr_version.h>

static pthread_once_t local_thread_engine_evl_init = PTHREAD_ONCE_INIT;
FLB_TLS_DEFINE(struct mk_event_loop, flb_engine_evl);

static void flb_engine_evl_init_private()
{
    FLB_TLS_INIT(flb_engine_evl);
}

void flb_engine_evl_init()
{
    pthread_once(&local_thread_engine_evl_init, flb_engine_evl_init_private);
}

struct mk_event_loop *flb_engine_evl_get()
{
    struct mk_event_loop *evl;

    evl = FLB_TLS_GET(flb_engine_evl);
    return evl;
}

void flb_engine_evl_set(struct mk_event_loop *evl)
{
    FLB_TLS_SET(flb_engine_evl, evl);
}

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

void flb_engine_reschedule_retries(struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct mk_list *t_head;
    struct mk_list *rt_head;
    struct mk_list *tmp_task;
    struct mk_list *tmp_retry_task;
    struct flb_task *task;
    struct flb_input_instance *ins;
    struct flb_task_retry *retry;

    /* Invalidate and reschedule all retry tasks to be retried immediately */
    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        mk_list_foreach_safe(t_head, tmp_task, &ins->tasks) {
            task = mk_list_entry(t_head, struct flb_task, _head);

            if (task->users > 0) {
                flb_debug("[engine] task %i already scheduled to run, not re-scheduling it.",
                    task->id
                );

                continue;
            }

            mk_list_foreach_safe(rt_head, tmp_retry_task, &task->retries) {
                retry = mk_list_entry(rt_head, struct flb_task_retry, _head);
                flb_sched_request_invalidate(config, retry);
                ret = flb_sched_retry_now(config, retry);
                if (ret == -1) {
                    /* Can't do much here, just continue on */
                    flb_warn("[engine] failed to immediately re-schedule retry=%p "
                             "for task %i. Err: %d", retry, task->id, flb_errno());
                } else {
                    flb_debug("[engine] re-scheduled retry=%p for task %i",
                        retry, task->id);
                }
            }
        }
    }
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

/* Cleanup function that runs every 1.5 second */
static void cb_engine_sched_timer(struct flb_config *ctx, void *data)
{
    (void) data;

    /* Upstream timeout handling */
    flb_upstream_conn_timeouts(&ctx->upstreams);

    /* Downstream timeout handling */
    flb_downstream_conn_timeouts(&ctx->downstreams);
}

static inline int handle_input_event(flb_pipefd_t fd, uint64_t ts,
                                     struct flb_config *config)
{
    int bytes;
    uint32_t type;
    uint32_t ins_id;
    uint64_t val;

    bytes = flb_pipe_r(fd, &val, sizeof(val));
    if (bytes == -1) {
        flb_pipe_error();
        return -1;
    }

    /* Get type and key */
    type   = FLB_BITS_U64_HIGH(val);
    ins_id = FLB_BITS_U64_LOW(val);

    /* At the moment we only support events coming from an input coroutine */
    if (type != FLB_ENGINE_IN_CORO) {
        flb_error("[engine] invalid event type %i for input handler",
                  type);
        return -1;
    }

    flb_input_coro_finished(config, (int) ins_id);
    return 0;
}

static inline double calculate_chunk_capacity_percent(struct flb_output_instance *ins)
{
    /* Currently, total_limit_size 0(K|M)B will be translated as no
     * limit. So, we need to handle this situation to be unlimited. */
    if (ins->total_limit_size <= 0) {
        return 100.0;
    }

    return 100 * (1.0 - (ins->fs_backlog_chunks_size + ins->fs_chunks_size)/
                  ((double)ins->total_limit_size));
}

static void handle_dlq_if_available(struct flb_config *config,
                                    struct flb_task *task,
                                    struct flb_output_instance *ins,
                                    int status_code /* pass 0 if unknown */)
{
    const char *tag_buf = NULL;
    int         tag_len = 0;
    flb_sds_t   tag_sds = NULL;
    const char *tag     = NULL;
    const char *out     = NULL;
    struct flb_input_chunk *ic;
    struct cio_chunk *cio_ch;

    if (!config || !config->storage_keep_rejected || !task || !task->ic || !ins) {
        return;
    }

    ic = (struct flb_input_chunk *) task->ic;

    if (!ic || !ic->chunk) {
        return;
    }

    /* Obtain tag from the input chunk API (no direct field available) */
    if (flb_input_chunk_get_tag(ic, &tag_buf, &tag_len) == 0 && tag_buf && tag_len > 0) {
        tag_sds = flb_sds_create_len(tag_buf, tag_len);  /* make it NUL-terminated */
        tag     = tag_sds;
    }
    else {
        /* Fallback: use input instance name */
        tag = flb_input_name(task->i_ins);
    }

    out    = flb_output_name(ins);
    cio_ch = (struct cio_chunk *) ic->chunk;  /* ic->chunk is a cio_chunk* under the hood */

    /* Copy bytes into DLQ stream (filesystem) */
    (void) flb_storage_quarantine_chunk(config, cio_ch, tag, status_code, out);

    if (tag_sds) {
        flb_sds_destroy(tag_sds);
    }
}

static inline int handle_output_event(uint64_t ts,
                                      struct flb_config *config,
                                      uint64_t val)
{
    int ret;
    int task_id;
    int out_id;
    int retries;
    int retry_seconds;
    uint32_t type;
    uint32_t key;
    double latency_seconds;
    char *in_name;
    char *out_name;
    struct flb_task *task;
    struct flb_task_retry *retry;
    struct flb_output_instance *ins;

    /* Get type and key */
    type = FLB_BITS_U64_HIGH(val);
    key  = FLB_BITS_U64_LOW(val);

    if (type != FLB_ENGINE_TASK) {
        flb_error("[engine] invalid event type %i for output handler",
                  type);
        return -1;
    }

    /*
     * The notion of ENGINE_TASK is associated to outputs. All thread
     * references below belongs to flb_output_coro's.
     */
    ret     = FLB_TASK_RET(key);
    task_id = FLB_TASK_ID(key);
    out_id  = FLB_TASK_OUT(key);

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

    flb_trace("%s[engine] [task event]%s task_id=%i out_id=%i return=%s",
              ANSI_YELLOW, ANSI_RESET,
              task_id, out_id, trace_st);
#endif

    task = config->task_map[task_id].task;
    ins  = flb_output_get_instance(config, out_id);
    if (flb_output_is_threaded(ins) == FLB_FALSE) {
        flb_output_flush_finished(config, out_id);
    }
    in_name = (char *) flb_input_name(task->i_ins);
    out_name = (char *) flb_output_name(ins);

    /* If we are in synchronous mode, flush the next waiting task */
    if (ins->flags & FLB_OUTPUT_SYNCHRONOUS) {
        if (ret == FLB_OK || ret == FLB_RETRY || ret == FLB_ERROR) {
            flb_output_task_singleplex_flush_next(ins->singleplex_queue);
        }
    }

    /* A task has finished, delete it */
    if (ret == FLB_OK) {
        /* cmetrics */
        cmt_counter_add(ins->cmt_proc_records, ts, task->event_chunk->total_events,
                        1, (char *[]) {out_name});

        cmt_counter_add(ins->cmt_proc_bytes, ts, task->event_chunk->size,
                        1, (char *[]) {out_name});

        if (config->router && task->event_chunk->type == FLB_EVENT_TYPE_LOGS) {
            cmt_counter_add(config->router->logs_records_total, ts,
                            task->event_chunk->total_events,
                            2, (char *[]) {in_name, out_name});

            cmt_counter_add(config->router->logs_bytes_total, ts,
                            task->event_chunk->size,
                            2, (char *[]) {in_name, out_name});
        }

        /* latency histogram */
        if (ins->cmt_latency) {
            latency_seconds = flb_time_now() - ((struct flb_input_chunk *) task->ic)->create_time;
            cmt_histogram_observe(ins->cmt_latency, ts, latency_seconds, 2,
                                  (char *[]) {in_name, out_name});
        }

        /* [OLD API] Update metrics */
#ifdef FLB_HAVE_METRICS
        if (ins->metrics) {
            flb_metrics_sum(FLB_METRIC_OUT_OK_RECORDS,
                            task->event_chunk->total_events, ins->metrics);
            flb_metrics_sum(FLB_METRIC_OUT_OK_BYTES,
                            task->event_chunk->size, ins->metrics);
        }
#endif
        /* Inform the user if a 'retry' succedeed */
        if (mk_list_size(&task->retries) > 0) {
            retries = flb_task_retry_count(task, ins);
            if (retries > 0) {
                flb_info("[engine] flush chunk '%s' succeeded at retry %i: "
                         "task_id=%i, input=%s > output=%s (out_id=%i)",
                         flb_input_chunk_get_name(task->ic),
                         retries, task_id,
                         flb_input_name(task->i_ins),
                         flb_output_name(ins), out_id);
            }
        }
        else if (flb_task_from_fs_storage(task) == FLB_TRUE) {
            flb_info("[engine] flush backlog chunk '%s' succeeded: "
                     "task_id=%i, input=%s > output=%s (out_id=%i)",
                     flb_input_chunk_get_name(task->ic),
                     task_id,
                     flb_input_name(task->i_ins),
                     flb_output_name(ins), out_id);
        }

        cmt_gauge_set(ins->cmt_chunk_available_capacity_percent, ts,
                      calculate_chunk_capacity_percent(ins),
                      1, (char *[]) {out_name});

        flb_task_retry_clean(task, ins);
        flb_task_users_dec(task, FLB_TRUE);
    }
    else if (ret == FLB_RETRY) {
        if (ins->retry_limit == FLB_OUT_RETRY_NONE) {
            handle_dlq_if_available(config, task, ins, 0);

            /* cmetrics: output_dropped_records_total */
            cmt_counter_add(ins->cmt_dropped_records, ts, task->records,
                            1, (char *[]) {out_name});

            if (config->router && task->event_chunk &&
                task->event_chunk->type == FLB_EVENT_TYPE_LOGS) {
                cmt_counter_add(config->router->logs_drop_records_total, ts,
                                task->records,
                                2, (char *[]) {in_name, out_name});

                cmt_counter_add(config->router->logs_drop_bytes_total, ts,
                                task->event_chunk->size,
                                2, (char *[]) {in_name, out_name});
            }

            cmt_gauge_set(ins->cmt_chunk_available_capacity_percent, ts,
                          calculate_chunk_capacity_percent(ins),
                          1, (char *[]) {out_name});

            /* OLD metrics API */
#ifdef FLB_HAVE_METRICS
            flb_metrics_sum(FLB_METRIC_OUT_DROPPED_RECORDS, task->records, ins->metrics);
#endif
            flb_info("[engine] chunk '%s' is not retried (no retry config): "
                     "task_id=%i, input=%s > output=%s (out_id=%i)",
                     flb_input_chunk_get_name(task->ic),
                     task_id,
                     flb_input_name(task->i_ins),
                     flb_output_name(ins), out_id);

            flb_task_retry_clean(task, ins);
            flb_task_users_dec(task, FLB_TRUE);

            return 0;
        }

        /* Create a Task-Retry */
        retry = flb_task_retry_create(task, ins);
        if (!retry) {
            /*
             * It can fail in two situations:
             *
             * - No enough memory (unlikely)
             * - It reached the maximum number of re-tries
             */

            handle_dlq_if_available(config, task, ins, 0);

            /* cmetrics */
            cmt_counter_inc(ins->cmt_retries_failed, ts, 1, (char *[]) {out_name});
            cmt_counter_add(ins->cmt_dropped_records, ts, task->records,
                            1, (char *[]) {out_name});

            if (config->router && task->event_chunk &&
                task->event_chunk->type == FLB_EVENT_TYPE_LOGS) {
                cmt_counter_add(config->router->logs_drop_records_total, ts,
                                task->records,
                                2, (char *[]) {in_name, out_name});

                cmt_counter_add(config->router->logs_drop_bytes_total, ts,
                                task->event_chunk->size,
                                2, (char *[]) {in_name, out_name});
            }

            cmt_gauge_set(ins->cmt_chunk_available_capacity_percent, ts,
                          calculate_chunk_capacity_percent(ins),
                          1, (char *[]) {out_name});

            /* OLD metrics API */
#ifdef FLB_HAVE_METRICS
            flb_metrics_sum(FLB_METRIC_OUT_RETRY_FAILED, 1, ins->metrics);
            flb_metrics_sum(FLB_METRIC_OUT_DROPPED_RECORDS, task->records, ins->metrics);
#endif
            /* Notify about this failed retry */
            flb_error("[engine] chunk '%s' cannot be retried: "
                      "task_id=%i, input=%s > output=%s",
                      flb_input_chunk_get_name(task->ic),
                      task_id,
                      flb_input_name(task->i_ins),
                      flb_output_name(ins));

            flb_task_retry_clean(task, ins);
            flb_task_users_dec(task, FLB_TRUE);

            return 0;
        }

        /* Always destroy the old coroutine */
        flb_task_users_dec(task, FLB_FALSE);

        /* Let the scheduler to retry the failed task/thread */
        retry_seconds = flb_sched_request_create(config,
                                                 retry, retry->attempts);

        /*
         * If for some reason the Scheduler could not include this retry,
         * we need to get rid of it, likely this is because of not enough
         * memory available or we ran out of file descriptors.
         */
        if (retry_seconds == -1) {
            handle_dlq_if_available(config, task, ins, 0);

            flb_warn("[engine] retry for chunk '%s' could not be scheduled: "
                     "input=%s > output=%s",
                     flb_input_chunk_get_name(task->ic),
                     flb_input_name(task->i_ins),
                     flb_output_name(ins));

            flb_task_retry_destroy(retry);
            flb_task_users_release(task);
        }
        else {
            /* Inform the user 'retry' has been scheduled */
            flb_warn("[engine] failed to flush chunk '%s', retry in %i seconds: "
                     "task_id=%i, input=%s > output=%s (out_id=%i)",
                     flb_input_chunk_get_name(task->ic),
                     retry_seconds,
                     task->id,
                     flb_input_name(task->i_ins),
                     flb_output_name(ins), out_id);

            /* cmetrics */
            cmt_counter_inc(ins->cmt_retries, ts, 1, (char *[]) {out_name});
            cmt_counter_add(ins->cmt_retried_records, ts, task->records,
                            1, (char *[]) {out_name});

            cmt_gauge_set(ins->cmt_chunk_available_capacity_percent, ts,
                          calculate_chunk_capacity_percent(ins),
                          1, (char *[]) {out_name});

            /* OLD metrics API: update the metrics since a new retry is coming */
#ifdef FLB_HAVE_METRICS
            flb_metrics_sum(FLB_METRIC_OUT_RETRY, 1, ins->metrics);
            flb_metrics_sum(FLB_METRIC_OUT_RETRIED_RECORDS, task->records, ins->metrics);
#endif
        }
    }
    else if (ret == FLB_ERROR) {
        handle_dlq_if_available(config, task, ins, 0);
        /* cmetrics */
        cmt_counter_inc(ins->cmt_errors, ts, 1, (char *[]) {out_name});
        cmt_counter_add(ins->cmt_dropped_records, ts, task->records,
                        1, (char *[]) {out_name});

        if (config->router && task->event_chunk &&
            task->event_chunk->type == FLB_EVENT_TYPE_LOGS) {
            cmt_counter_add(config->router->logs_drop_records_total, ts,
                            task->records,
                            2, (char *[]) {in_name, out_name});

            cmt_counter_add(config->router->logs_drop_bytes_total, ts,
                            task->event_chunk->size,
                            2, (char *[]) {in_name, out_name});
        }

        cmt_gauge_set(ins->cmt_chunk_available_capacity_percent, ts,
                      calculate_chunk_capacity_percent(ins),
                      1, (char *[]) {out_name});

        /* OLD API */
#ifdef FLB_HAVE_METRICS
        flb_metrics_sum(FLB_METRIC_OUT_ERROR, 1, ins->metrics);
        flb_metrics_sum(FLB_METRIC_OUT_DROPPED_RECORDS, task->records, ins->metrics);
#endif

        flb_task_retry_clean(task, ins);
        flb_task_users_dec(task, FLB_TRUE);
    }

    return 0;
}

static inline int handle_output_events(flb_pipefd_t fd,
                                       struct flb_config *config)
{
    uint64_t values[FLB_ENGINE_OUTPUT_EVENT_BATCH_SIZE];
    int      result;
    int      bytes;
    size_t   limit;
    size_t   index;
    uint64_t ts;

    memset(&values, 0, sizeof(values));

    bytes = flb_pipe_r(fd, &values, sizeof(values));

    if (bytes == -1) {
        flb_pipe_error();
        return -1;
    }

    limit = floor(bytes / sizeof(uint64_t));

    ts = cfl_time_now();

    for (index = 0 ;
         index < limit &&
         index < (sizeof(values) / sizeof(values[0])) ;
         index++) {
        if (values[index] == 0) {
            break;
        }

        result = handle_output_event(ts, config, values[index]);
    }

    /* This is wrong, in one hand, if handle_output_event_ fails we should
     * stop, on the other, we have already consumed the signals from the pipe
     * so we have to do whatever we can with them.
     *
     * And a side effect is that since we have N results but we are not aborting
     * as soon as we get an error there could be N results to this function which
     * not only are we not ready to handle but is not even checked at the moment.
    */

    return result;
}

static inline int flb_engine_manager(flb_pipefd_t fd, struct flb_config *config)
{
    int bytes;
    uint32_t type;
    uint32_t key;
    uint64_t val;

    /* read the event */
    bytes = flb_pipe_r(fd, &val, sizeof(val));
    if (bytes == -1) {
        flb_pipe_error();
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

    return 0;
}

static FLB_INLINE int flb_engine_handle_event(flb_pipefd_t fd, int mask,
                                              struct flb_config *config)
{
    int64_t ret;

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
            flb_utils_timer_consume(fd);
            return FLB_ENGINE_SHUTDOWN;
        }
        else if (config->ch_manager[0] == fd) {
            ret = flb_engine_manager(fd, config);
            if (ret == FLB_ENGINE_STOP || ret == FLB_ENGINE_EV_STOP) {
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

        /* Stream processor event ? */
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
        flb_error("[engine] no channel to notify FAILED message");
        return -1;
    }

    val = FLB_ENGINE_FAILED;
    ret = flb_pipe_w(config->ch_notif[1], &val, sizeof(uint64_t));
    if (ret == -1) {
        flb_error("[engine] fail to dispatch FAILED message");
    }

    /* Waiting flushing log */
    sleep(1);

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

    if (flb_log_create(config, type, level, config->log_file) == NULL) {
        return -1;
    }

    return 0;
}

static void flb_engine_drain_ring_buffer_signal_channel(flb_pipefd_t fd)
{
    static char signal_buffer[512];

    flb_pipe_r(fd, signal_buffer, sizeof(signal_buffer));
}


#ifdef FLB_HAVE_IN_STORAGE_BACKLOG
extern int sb_segregate_chunks(struct flb_config *config);
#else
int sb_segregate_chunks(struct flb_config *config)
{
    return 0;
}
#endif

int flb_engine_start(struct flb_config *config)
{
    int ret;
    int tasks = 0;
    int fs_chunks = 0;
    int mem_chunks = 0;
    uint64_t ts;
    char tmp[16];
    int rb_flush_flag;
    struct flb_time t_flush;
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct flb_bucket_queue *evl_bktq;
    struct flb_sched *sched;
    struct flb_net_dns dns_ctx;
    struct flb_notification *notification;

    /* Initialize the networking layer */
    flb_net_lib_init();
    flb_net_ctx_init(&dns_ctx);
    flb_net_dns_ctx_init();
    flb_net_dns_ctx_set(&dns_ctx);

    flb_pack_init(config);

    /* Create the event loop and set it in the global configuration */
    evl = mk_event_loop_create(256);
    if (!evl) {
        fprintf(stderr, "[log] could not create event loop\n");
        return -1;
    }
    config->evl = evl;

    /* Create the bucket queue (FLB_ENGINE_PRIORITY_COUNT priorities) */
    evl_bktq = flb_bucket_queue_create(FLB_ENGINE_PRIORITY_COUNT);
    if (!evl_bktq) {
        return -1;
    }
    config->evl_bktq = evl_bktq;

    /*
     * Event loop channel to ingest flush events from flb_engine_flush()
     *
     *  - FLB engine uses 'ch_self_events[1]' to dispatch tasks to self
     *  - Self to receive message on ch_parent_events[0]
     *
     * The mk_event_channel_create() will attach the pipe read end ch_self_events[0]
     * to the local event loop 'evl'.
     */
    ret = mk_event_channel_create(config->evl,
                                  &config->ch_self_events[0],
                                  &config->ch_self_events[1],
                                  &config->event_thread_init);
    if (ret == -1) {
        flb_error("[engine] could not create engine thread channel");
        return -1;
    }
    /* Signal type to indicate a "flush" request */
    config->event_thread_init.type = FLB_ENGINE_EV_THREAD_ENGINE;
    config->event_thread_init.priority = FLB_ENGINE_PRIORITY_THREAD;

    /* Register the event loop on this thread */
    flb_engine_evl_init();
    flb_engine_evl_set(evl);

    /* Start the Logging service */
    ret = flb_engine_log_start(config);
    if (ret == -1) {
        fprintf(stderr, "[engine] log start failed\n");
        return -1;
    }

    flb_info("[fluent bit] version=%s, commit=%.10s, pid=%i",
             FLB_VERSION_STR, FLB_GIT_HASH, getpid());

#ifdef FLB_SYSTEM_WINDOWS
    flb_debug("[engine] maxstdio set: %d", _getmaxstdio());
#endif
    /* Debug coroutine stack size */
    flb_utils_bytes_to_human_readable_size(config->coro_stack_size,
                                           tmp, sizeof(tmp));
    flb_debug("[engine] coroutine stack size: %u bytes (%s)",
              config->coro_stack_size, tmp);

    /*
     * Create a communication channel: this routine creates a channel to
     * signal the Engine event loop. It's useful to stop the event loop
     * or to instruct anything else without break.
     */
    ret = mk_event_channel_create(config->evl,
                                  &config->ch_manager[0],
                                  &config->ch_manager[1],
                                  &config->ch_event);
    if (ret != 0) {
        flb_error("[engine] could not create manager channels");
        return -1;
    }

    ret = mk_event_channel_create(config->evl,
                                  &config->notification_channels[0],
                                  &config->notification_channels[1],
                                  &config->notification_event);
    if (ret == -1) {
        flb_error("could not create main notification channel");

        return -1;
    }

    config->notification_channels_initialized = FLB_TRUE;
    config->notification_event.type = FLB_ENGINE_EV_NOTIFICATION;

    ret = flb_routes_mask_set_size(mk_list_size(&config->outputs), config->router);

    if (ret != 0) {
        flb_error("[engine] routing mask dimensioning failed");
        return -1;
    }

    /* Initialize custom plugins */
    ret = flb_custom_init_all(config);
    if (ret == -1) {
        return -1;
    }

    /* Start the Storage engine */
    ret = flb_storage_create(config);
    if (ret == -1) {
        flb_error("[engine] storage creation failed");
        return -1;
    }

    /* Internals */
    flb_info("[simd    ] %s", flb_simd_info());

    /* Init Metrics engine */
    cmt_initialize();
    flb_info("[cmetrics] version=%s", cmt_version());
    flb_info("[ctraces ] version=%s", ctr_version());

    /* Initialize the scheduler */
    sched = flb_sched_create(config, config->evl);
    if (!sched) {
        flb_error("[engine] scheduler could not start");
        return -1;
    }
    config->sched = sched;

    /* Register the scheduler context */
    flb_sched_ctx_init();
    flb_sched_ctx_set(sched);

    /* Initialize input plugins */
    ret = flb_input_init_all(config);
    if (ret == -1) {
        flb_error("[engine] input initialization failed");
        return -1;
    }

    /* Initialize filter plugins */
    ret = flb_filter_init_all(config);
    if (ret == -1) {
        flb_error("[engine] filter initialization failed");
        return -1;
    }

    /* Inputs pre-run */
    flb_input_pre_run_all(config);

    /* Initialize output plugins */
    ret = flb_output_init_all(config);
    if (ret == -1) {
        flb_error("[engine] output initialization failed");
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
    event->priority = FLB_ENGINE_PRIORITY_FLUSH;
    if (config->flush_fd == -1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH_CREATE);
    }


#ifdef FLB_HAVE_METRICS
    if (config->storage_metrics == FLB_TRUE) {
        config->storage_metrics_ctx = flb_storage_metrics_create(config);
    }
#endif

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

    /* Initialize collectors */
    flb_input_collectors_start(config);

    /*
     * Sched a permanent callback triggered every 1.5 second to let other
     * Fluent Bit components run tasks at that interval.
     */
    ret = flb_sched_timer_cb_create(config->sched,
                                    FLB_SCHED_TIMER_CB_PERM,
                                    1500, cb_engine_sched_timer, config, NULL);
    if (ret == -1) {
        flb_error("[engine] could not schedule permanent callback");
        return -1;
    }

    /* DEV/TEST change only */
    int rb_ms;
    char *rb_env;

    rb_env = getenv("FLB_DEV_RB_MS");
    if (!rb_env) {
        rb_ms = 250;
    }
    else {
        rb_ms = atoi(rb_env);
    }

    /* Input instance / Ring buffer collector */
    ret = flb_sched_timer_cb_create(config->sched,
                                    FLB_SCHED_TIMER_CB_PERM,
                                    rb_ms, flb_input_chunk_ring_buffer_collector,
                                    config, NULL);
    if (ret == -1) {
        flb_error("[engine] could not schedule permanent callback");
        return -1;
    }

    /* Signal that we have started */
    flb_engine_started(config);

    ret = sb_segregate_chunks(config);

    if (ret < 0)
    {
        flb_error("[engine] could not segregate backlog chunks");
        return -2;
    }

    config->grace_input  = config->grace / 2;
    flb_info("[engine] Shutdown Grace Period=%d, Shutdown Input Grace Period=%d", config->grace, config->grace_input);

    while (1) {
        rb_flush_flag = FLB_FALSE;

        mk_event_wait(evl); /* potentially conditional mk_event_wait or mk_event_wait_2 based on bucket queue capacity for one shot events */
        flb_event_priority_live_foreach(event, evl_bktq, evl, FLB_ENGINE_LOOP_MAX_ITER) {
            if (event->type == FLB_ENGINE_EV_CORE) {
                ret = flb_engine_handle_event(event->fd, event->mask, config);

                /*
                 * This block will be called once on engine stop.
                 * Will reschedule task to 1 sec. retry.
                 * Also timer with shutdown event will be created.
                 */
                if (ret == FLB_ENGINE_STOP) {
                    if (config->grace_count == 0) {
                        if (config->grace >= 0) {
                            flb_warn("[engine] service will shutdown in max %u seconds",
                                 config->grace);
                        } else {
                            flb_warn("[engine] service will shutdown when all remaining tasks are flushed");
                        }

                        /* Reschedule retry tasks to be retried immediately */
                        flb_engine_reschedule_retries(config);
                    }

                    /* mark the runtime as the ingestion is not active and that we are in shutting down mode */
                    flb_engine_stop_ingestion(config);

                    /*
                     * We are preparing to shutdown, we give a graceful time
                     * of 'config->grace' seconds to process any pending event.
                     */
                    event = &config->event_shutdown;
                    event->mask = MK_EVENT_EMPTY;
                    event->status = MK_EVENT_NONE;
                    event->priority = FLB_ENGINE_PRIORITY_SHUTDOWN;

                    /*
                     * Configure a timer of 1 second, on expiration the code will
                     * jump into the FLB_ENGINE_SHUTDOWN condition where it will
                     * check if the grace period has finished, or if there are
                     * any remaining tasks.
                     *
                     * If no tasks exists, there is no need to wait for the maximum
                     * grace period.
                     */
                    if (config->shutdown_fd <= 0) {
                        config->shutdown_fd = mk_event_timeout_create(evl,
                                                                      1,
                                                                      0,
                                                                      event);

	                    if (config->shutdown_fd == -1) {
	                        flb_error("[engine] could not create shutdown timer");
	                        /* fail early so we don't silently skip scheduled shutdown */
	                        return -1;
	                    }
                    }
                }
                else if (ret == FLB_ENGINE_SHUTDOWN) {
                    /* Increase the grace counter */
                    config->grace_count++;

                    /*
                     * Grace timeout has finished, but we need to check if there is
                     * any pending running task. A running task is associated to an
                     * output co-routine, since we don't know what's the state or
                     * resources allocated by that co-routine, the best thing is to
                     * wait again for the grace period and re-check again.
                     * If grace period is set to -1, keep trying to shut down until all
                     * tasks and retries get flushed.
                     */
                    tasks = 0;
                    mem_chunks = 0;
                    fs_chunks = 0;
                    tasks = flb_task_running_count(config);
                    flb_storage_chunk_count(config, &mem_chunks, &fs_chunks);

                    if ((mem_chunks + fs_chunks) > 0) {
                        flb_info("[engine] pending chunk count: memory=%d, filesystem=%d; grace_timer=%d",
                                 mem_chunks, fs_chunks, config->grace_count);
                    }

                    if (tasks > 0) {
                        flb_task_running_print(config);
                    }

                    ret = tasks + mem_chunks + fs_chunks;
                    if (ret > 0 && (config->grace_count < config->grace || config->grace == -1)) {
                        if (config->grace_count == 1) {
                            /*
                            * If storage.backlog.shutdown_flush is enabled, attempt to flush pending
                            * filesystem chunks during shutdown. This is particularly useful in scenarios
                            * where Fluent Bit cannot restart to ensure buffered data is not lost.
                            */
                            if (config->storage_bl_flush_on_shutdown) {
                                ret = sb_segregate_chunks(config);
                                if (ret < 0) {
                                    flb_error("[engine] could not segregate backlog chunks during shutdown");
                                    return -2;
                                }
                            }
                        }
                        /* Create new tasks for pending chunks */
                        flb_engine_flush(config, NULL);
                    }
                    else {
                        flb_info("[engine] service has stopped (%i pending tasks)",
                                 tasks);
                        ret = config->exit_status_code;
                        flb_engine_shutdown(config);

                        if (config->shutdown_fd > 0) {
                            mk_event_timeout_destroy(config->evl,
                                                     &config->event_shutdown);
                        }

                        return ret;
                    }
                }
            }
            else if (event->type & FLB_ENGINE_EV_SCHED) {
                /* Event type registered by the Scheduler */
                flb_sched_event_handler(config, event);
            }
            else if (event->type == FLB_ENGINE_EV_THREAD_ENGINE) {
                struct flb_output_flush *output_flush;

                /* Read the coroutine reference */
                ret = flb_pipe_r(event->fd, &output_flush, sizeof(struct flb_output_flush *));
                if (ret <= 0 || output_flush == 0) {
                    flb_pipe_error();
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

                if (connection->coroutine) {
                    flb_trace("[engine] resuming coroutine=%p", connection->coroutine);

                    flb_coro_resume(connection->coroutine);
                }
            }
            else if (event->type == FLB_ENGINE_EV_OUTPUT) {
                /*
                 * Event originated by an output plugin. likely a Task return
                 * status.
                 */
                handle_output_events(event->fd, config);
            }
            else if (event->type == FLB_ENGINE_EV_INPUT) {
                ts = cfl_time_now();
                handle_input_event(event->fd, ts, config);
            }
            else if(event->type == FLB_ENGINE_EV_THREAD_INPUT) {
                flb_engine_drain_ring_buffer_signal_channel(event->fd);

                rb_flush_flag = FLB_TRUE;
            }
            else if(event->type == FLB_ENGINE_EV_NOTIFICATION) {
                ret = flb_notification_receive(event->fd, &notification);

                if (ret == 0) {
                    ret = flb_notification_deliver(notification);

                    flb_notification_cleanup(notification);
                }
            }
        }

        if (rb_flush_flag) {
            flb_input_chunk_ring_buffer_collector(config, NULL);
        }

        /* Cleanup functions associated to events and timers */
        if (config->is_running == FLB_TRUE) {
            flb_net_dns_lookup_context_cleanup(&dns_ctx);
            flb_sched_timer_cleanup(config->sched);
            flb_upstream_conn_pending_destroy_list(&config->upstreams);
            flb_downstream_conn_pending_destroy_list(&config->downstreams);

            /*
            * depend on main thread to clean up expired message
            * in aws error reporting message queue
            */
            #ifdef FLB_HAVE_AWS_ERROR_REPORTER
            if (is_error_reporting_enabled()) {
                flb_aws_error_reporter_clean(error_reporter);
            }
            #endif
        }
    }
}

/* Release all resources associated to the engine */
int flb_engine_shutdown(struct flb_config *config)
{
    struct flb_sched_timer_coro_cb_params *sched_params;

    config->is_running = FLB_FALSE;
    config->is_ingestion_active = FLB_FALSE;
    flb_input_pause_all(config);

#ifdef FLB_HAVE_STREAM_PROCESSOR
    if (config->stream_processor_ctx) {
        flb_sp_destroy(config->stream_processor_ctx);
    }
#endif

    /* router */
    flb_router_exit(config);

    /* cleanup plugins */
    flb_filter_exit(config);
    flb_output_exit(config);
    flb_custom_exit(config);
    flb_input_exit_all(config);

    /* scheduler */
    sched_params = (struct flb_sched_timer_coro_cb_params *) FLB_TLS_GET(sched_timer_coro_cb_params);
    if (sched_params && sched_params->magic == FLB_SCHED_TLS_MAGIC) {
        flb_free(sched_params);
        FLB_TLS_SET(sched_timer_coro_cb_params, NULL);
    }

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
    if (config->evl) {
        mk_event_channel_destroy(config->evl,
                                 config->ch_self_events[0],
                                 config->ch_self_events[1],
                                 &config->event_thread_init);
    }

    if (config->notification_channels_initialized == FLB_TRUE) {
        mk_event_channel_destroy(config->evl,
                                 config->notification_channels[0],
                                 config->notification_channels[1],
                                 &config->notification_event);

        config->notification_channels_initialized = FLB_FALSE;
    }

    return 0;
}

int flb_engine_exit(struct flb_config *config)
{
    int ret;
    uint64_t val;

    val = FLB_ENGINE_EV_STOP;
    ret = flb_pipe_w(config->ch_manager[1], &val, sizeof(uint64_t));
    return ret;
}

/* Stop ingestion and pause all inputs */
void flb_engine_stop_ingestion(struct flb_config *config)
{
    config->is_ingestion_active = FLB_FALSE;
    config->is_shutting_down = FLB_TRUE;

    flb_info("[engine] pausing all inputs..");
    flb_input_pause_all(config);
}

int flb_engine_exit_status(struct flb_config *config, int status)
{
    config->exit_status_code = status;
    return flb_engine_exit(config);
}
