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

#include <errno.h>
#include <limits.h>
#include <time.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_input_profiles.h>
#include <fluent-bit/flb_input_trace.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_ring_buffer.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/http_server/flb_http_server_config.h>

#include <cprofiles/cprof_encode_msgpack.h>

enum flb_input_ingress_event_type {
    FLB_INPUT_INGRESS_LOG = 0,
    FLB_INPUT_INGRESS_METRICS,
    FLB_INPUT_INGRESS_TRACES,
    FLB_INPUT_INGRESS_PROFILES,
    FLB_INPUT_INGRESS_RAW          /* host payload for the plugin cb_ingest */
};

struct flb_input_ingress_event {
    int type;
    flb_sds_t tag;
    size_t size;
    int metrics_resume;
    size_t metrics_starting_stage;

    union {
        struct {
            void   *buf;
            size_t  size;
            size_t  records;
            int     processed;
            int     resume;
            size_t  starting_stage;
        } log;
        struct ctrace *traces;
        struct cprof  *profiles;
        struct {
            /* The view points into the storage that trails this struct */
            struct flb_input_ingest_event view;
            flb_input_ingest_reply_cb     reply_cb;
            void                         *reply_data;
            int                           replied;
        } raw;
    } data;

    struct cfl_list metrics;
    struct mk_list _head;
};

static void flb_input_ingest_event_settle(struct flb_input_ingress_event *event,
                                          int outcome);

static void flb_input_ingress_event_destroy(struct flb_input_ingress_event *event)
{
    struct cfl_list *iterator;
    struct cfl_list *tmp;
    struct cmt *context;

    if (event == NULL) {
        return;
    }

    if (!mk_list_entry_is_orphan(&event->_head)) {
        mk_list_del(&event->_head);
    }

    if (event->tag != NULL) {
        flb_sds_destroy(event->tag);
    }

    if (event->type == FLB_INPUT_INGRESS_LOG) {
        if (event->data.log.buf != NULL) {
            flb_free(event->data.log.buf);
        }
    }
    else if (event->type == FLB_INPUT_INGRESS_METRICS) {
        cfl_list_foreach_safe(iterator, tmp, &event->metrics) {
            context = cfl_list_entry(iterator, struct cmt, _head);
            cfl_list_del(&context->_head);
            cmt_destroy(context);
        }
    }
    else if (event->type == FLB_INPUT_INGRESS_TRACES) {
        if (event->data.traces != NULL) {
            ctr_destroy(event->data.traces);
        }
    }
    else if (event->type == FLB_INPUT_INGRESS_PROFILES) {
        if (event->data.profiles != NULL) {
            cprof_destroy(event->data.profiles);
        }
    }

    flb_free(event);
}

static size_t flb_input_ingress_event_size(struct flb_input_ingress_event *event)
{
    if (event == NULL) {
        return 0;
    }

    return event->size;
}

static size_t flb_input_ingress_signal_size(size_t payload_size)
{
    if (payload_size > 0) {
        return payload_size;
    }

    /* Callers should provide the source payload size. Keep a non-zero fallback
     * for producers that legitimately build a signal without a wire payload.
     */
    return 64 * 1024;
}

static void flb_input_ingress_signal(struct flb_input_instance *ins)
{
    int result;
    char signal = '.';

    result = flb_pipe_w(ins->ingress_queue_channels[1], &signal, sizeof(signal));
    if (result == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
        flb_errno();
    }
}

static void flb_input_ingress_update_metrics(struct flb_input_instance *ins)
{
    uint64_t ts;
    char *name;

    if (ins == NULL || ins->cmt == NULL) {
        return;
    }

    ts = cfl_time_now();
    name = (char *) flb_input_name(ins);

    if (ins->cmt_ingress_queue_pending_events != NULL) {
        cmt_gauge_set(ins->cmt_ingress_queue_pending_events,
                      ts,
                      ins->ingress_queue_pending_events,
                      1, (char *[]) {name});
    }

    if (ins->cmt_ingress_queue_pending_bytes != NULL) {
        cmt_gauge_set(ins->cmt_ingress_queue_pending_bytes,
                      ts,
                      ins->ingress_queue_pending_bytes,
                      1, (char *[]) {name});
    }
}

static int flb_input_ingress_busy(struct flb_input_instance *ins,
                                  struct flb_input_ingress_event *event)
{
    struct cmt_counter *counter;
    flb_sds_t input_name;

    counter = ins->cmt_ingress_queue_busy;
    input_name = NULL;

    if (counter != NULL) {
        input_name = flb_sds_create(flb_input_name(ins));
    }

    if (counter != NULL && input_name != NULL) {
        cmt_counter_add(counter, cfl_time_now(), 1, 1, (char *[]) {input_name});
        flb_sds_destroy(input_name);
    }

    flb_input_ingress_event_destroy(event);

    return FLB_INPUT_INGRESS_BUSY;
}

static int flb_input_ingress_enqueue(struct flb_input_instance *ins,
                                     struct flb_input_ingress_event *event)
{
    size_t event_size;
    int queue_is_full;
    int should_signal;
    int wait_result;
    struct timespec deadline;

    if (ins == NULL || event == NULL || ins->ingress_queue_enabled != FLB_TRUE) {
        flb_input_ingress_event_destroy(event);
        return -1;
    }

    event_size = flb_input_ingress_event_size(event);
    should_signal = FLB_FALSE;

    pthread_mutex_lock(&ins->ingress_queue_lock);

    if (ins->ingress_queue_byte_limit > 0 &&
        event_size > ins->ingress_queue_byte_limit) {
        pthread_mutex_unlock(&ins->ingress_queue_lock);
        return flb_input_ingress_busy(ins, event);
    }

    while (ins->ingress_queue_enabled == FLB_TRUE) {
        queue_is_full = FLB_FALSE;

        if (ins->ingress_queue_event_limit > 0 &&
            ins->ingress_queue_pending_events >= ins->ingress_queue_event_limit) {
            queue_is_full = FLB_TRUE;
        }

        if (ins->ingress_queue_byte_limit > 0) {
            if (event_size > ins->ingress_queue_byte_limit ||
                ins->ingress_queue_pending_bytes >
                    ins->ingress_queue_byte_limit - event_size) {
                queue_is_full = FLB_TRUE;
            }
        }

        if (queue_is_full == FLB_FALSE) {
            break;
        }

#if defined(FLB_SYSTEM_WINDOWS)
        timespec_get(&deadline, TIME_UTC);
#elif defined(CLOCK_MONOTONIC) && !defined(FLB_SYSTEM_MACOS)
        clock_gettime(CLOCK_MONOTONIC, &deadline);
#else
        clock_gettime(CLOCK_REALTIME, &deadline);
#endif
        deadline.tv_nsec += 100 * 1000 * 1000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }

        wait_result = pthread_cond_timedwait(&ins->ingress_queue_space_available,
                                             &ins->ingress_queue_lock,
                                             &deadline);
        if (wait_result == ETIMEDOUT) {
            pthread_mutex_unlock(&ins->ingress_queue_lock);
            return flb_input_ingress_busy(ins, event);
        }
        else if (wait_result != 0) {
            pthread_mutex_unlock(&ins->ingress_queue_lock);
            flb_input_ingress_event_destroy(event);
            return -1;
        }
    }

    if (ins->ingress_queue_enabled != FLB_TRUE) {
        pthread_mutex_unlock(&ins->ingress_queue_lock);

        flb_input_ingress_event_destroy(event);

        return FLB_INPUT_INGRESS_BUSY;
    }

    mk_list_add(&event->_head, &ins->ingress_queue);
    ins->ingress_queue_pending_events++;
    ins->ingress_queue_pending_bytes += event_size;
    flb_input_ingress_update_metrics(ins);

    if (ins->ingress_queue_signal_pending == FLB_FALSE) {
        ins->ingress_queue_signal_pending = FLB_TRUE;
        should_signal = FLB_TRUE;
    }

    pthread_mutex_unlock(&ins->ingress_queue_lock);

    if (should_signal == FLB_TRUE) {
        flb_input_ingress_signal(ins);
    }

    return 0;
}

static struct flb_input_ingress_event *flb_input_ingress_event_create(
    int type,
    const char *tag,
    size_t tag_len)
{
    struct flb_input_ingress_event *event;

    event = flb_calloc(1, sizeof(struct flb_input_ingress_event));
    if (event == NULL) {
        flb_errno();
        return NULL;
    }

    event->type = type;
    cfl_list_init(&event->metrics);
    mk_list_entry_init(&event->_head);

    if (tag != NULL && tag_len > 0) {
        event->tag = flb_sds_create_len(tag, tag_len);
        if (event->tag == NULL) {
            flb_input_ingress_event_destroy(event);
            return NULL;
        }
    }

    return event;
}

int flb_input_ingress_try_resume_log(struct flb_input_instance *ins,
                                     size_t starting_stage,
                                     const char *tag, size_t tag_len,
                                     void **buf, size_t buf_size, size_t records)
{
    int should_signal;
    struct flb_input_ingress_event *event;

    if (ins == NULL || buf == NULL || *buf == NULL || buf_size == 0 ||
        (tag == NULL && tag_len != 0) || tag_len > INT_MAX) {
        return -1;
    }

    /* Allocate only the envelope/tag. Until publication it owns no payload. */
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_LOG, tag, tag_len);
    if (event == NULL) {
        return -1;
    }
    event->size = buf_size;
    event->data.log.size = buf_size;
    event->data.log.records = records;
    event->data.log.resume = FLB_TRUE;
    event->data.log.starting_stage = starting_stage;

    pthread_mutex_lock(&ins->ingress_queue_lock);
    if (ins->ingress_queue_enabled != FLB_TRUE) {
        pthread_mutex_unlock(&ins->ingress_queue_lock);
        flb_input_ingress_event_destroy(event);
        return -1;
    }
    if ((ins->ingress_queue_event_limit > 0 &&
         ins->ingress_queue_pending_events >= ins->ingress_queue_event_limit) ||
        (ins->ingress_queue_byte_limit > 0 &&
         (buf_size > ins->ingress_queue_byte_limit ||
          ins->ingress_queue_pending_bytes > ins->ingress_queue_byte_limit - buf_size)) ||
        ins->ingress_queue_pending_bytes > SIZE_MAX - buf_size ||
        ins->ingress_queue_pending_events == SIZE_MAX) {
        pthread_mutex_unlock(&ins->ingress_queue_lock);
        return flb_input_ingress_busy(ins, event);
    }

    event->data.log.buf = *buf;
    *buf = NULL;
    mk_list_add(&event->_head, &ins->ingress_queue);
    ins->ingress_queue_pending_events++;
    ins->ingress_queue_pending_bytes += buf_size;
    flb_input_ingress_update_metrics(ins);
    should_signal = ins->ingress_queue_signal_pending == FLB_FALSE;
    ins->ingress_queue_signal_pending = FLB_TRUE;
    pthread_mutex_unlock(&ins->ingress_queue_lock);

    if (should_signal) {
        flb_input_ingress_signal(ins);
    }
    return 0;
}

int flb_input_ingress_try_resume_metrics(struct flb_input_instance *ins,
                                         size_t starting_stage,
                                         const char *tag, size_t tag_len,
                                         struct cmt **context, size_t payload_size)
{
    int should_signal;
    struct flb_input_ingress_event *event;

    if (ins == NULL || context == NULL || *context == NULL || payload_size == 0 ||
        (tag == NULL && tag_len != 0) || tag_len > INT_MAX) {
        return -1;
    }
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_METRICS, tag, tag_len);
    if (event == NULL) {
        return -1;
    }
    event->size = payload_size;
    event->metrics_resume = FLB_TRUE;
    event->metrics_starting_stage = starting_stage;

    pthread_mutex_lock(&ins->ingress_queue_lock);
    if (ins->ingress_queue_enabled != FLB_TRUE) {
        pthread_mutex_unlock(&ins->ingress_queue_lock);
        flb_input_ingress_event_destroy(event);
        return -1;
    }
    if ((ins->ingress_queue_event_limit > 0 &&
         ins->ingress_queue_pending_events >= ins->ingress_queue_event_limit) ||
        (ins->ingress_queue_byte_limit > 0 &&
         (payload_size > ins->ingress_queue_byte_limit ||
          ins->ingress_queue_pending_bytes > ins->ingress_queue_byte_limit - payload_size)) ||
        ins->ingress_queue_pending_bytes > SIZE_MAX - payload_size ||
        ins->ingress_queue_pending_events == SIZE_MAX) {
        pthread_mutex_unlock(&ins->ingress_queue_lock);
        return flb_input_ingress_busy(ins, event);
    }

    if (!cfl_list_entry_is_orphan(&(*context)->_head)) {
        cfl_list_del(&(*context)->_head);
    }
    cfl_list_add(&(*context)->_head, &event->metrics);
    *context = NULL;
    mk_list_add(&event->_head, &ins->ingress_queue);
    ins->ingress_queue_pending_events++;
    ins->ingress_queue_pending_bytes += payload_size;
    flb_input_ingress_update_metrics(ins);
    should_signal = ins->ingress_queue_signal_pending == FLB_FALSE;
    ins->ingress_queue_signal_pending = FLB_TRUE;
    pthread_mutex_unlock(&ins->ingress_queue_lock);

    if (should_signal) {
        flb_input_ingress_signal(ins);
    }
    return 0;
}

static void flb_input_ingress_drain_signal(struct flb_input_instance *ins)
{
    int result;
    char buffer[32];

    do {
        result = flb_pipe_r(ins->ingress_queue_channels[0],
                            buffer,
                            sizeof(buffer));
    }
    while (result > 0);
}

static int flb_input_ingress_collector(struct flb_input_instance *ins,
                                       struct flb_config *config,
                                       void *context)
{
    int result;
    size_t raw_events;
    size_t raw_bytes;
    struct flb_input_ingress_event *event;
    struct cmt *metrics_context;

    (void) config;
    (void) context;

    raw_events = 0;
    raw_bytes = 0;

    flb_input_ingress_drain_signal(ins);
    while (FLB_TRUE) {
        pthread_mutex_lock(&ins->ingress_queue_lock);
        if (mk_list_is_empty(&ins->ingress_queue) == 0) {
            ins->ingress_queue_signal_pending = FLB_FALSE;
            pthread_mutex_unlock(&ins->ingress_queue_lock);
            break;
        }
        /* Host payloads are parsed here, on the engine loop: bound the work
         * of one pass and rearm so the remaining events do not depend on a
         * later submission. */
        if (raw_events >= FLB_INPUT_INGEST_PASS_EVENTS ||
            raw_bytes >= FLB_INPUT_INGEST_PASS_BYTES) {
            ins->ingress_queue_signal_pending = FLB_TRUE;
            pthread_mutex_unlock(&ins->ingress_queue_lock);
            flb_input_ingress_signal(ins);
            return 0;
        }
        /* Pause before invoking downstream processors: a generic append error
         * can follow partial publication and must never be blindly retried. */
        if (flb_input_paused(ins) == FLB_TRUE &&
            (ins->config->is_shutting_down == FLB_FALSE ||
             (ins->flags & FLB_INPUT_SHUTDOWN_FLUSH) == 0)) {
            ins->ingress_queue_signal_pending = FLB_TRUE;
            pthread_mutex_unlock(&ins->ingress_queue_lock);
            flb_input_collector_pause(ins->ingress_queue_collector_id, ins);
            flb_input_ingress_signal(ins);
            return 0;
        }
        event = mk_list_entry(ins->ingress_queue.next, struct flb_input_ingress_event, _head);
        mk_list_del(&event->_head);
        mk_list_entry_init(&event->_head);
        /* In-flight events continue counting against queue bounds until their
         * append settles, so concurrent producers cannot overfill a paused queue. */
        pthread_mutex_unlock(&ins->ingress_queue_lock);

        if (event->type == FLB_INPUT_INGRESS_LOG) {
            if (event->data.log.resume == FLB_TRUE) {
                result = flb_input_log_append_skip_processor_stages(
                            ins, event->data.log.starting_stage,
                            event->tag,
                            event->tag != NULL ? flb_sds_len(event->tag) : 0,
                            event->data.log.buf, event->data.log.size);
            }
            else if (event->data.log.processed == FLB_TRUE) {
                result = flb_input_log_append_processed_routed(
                            ins,
                            event->data.log.records,
                            event->tag,
                            event->tag != NULL ? flb_sds_len(event->tag) : 0,
                            event->data.log.buf,
                            event->data.log.size);
            }
            else if (event->data.log.records > 0) {
                result = flb_input_log_append_records(
                            ins,
                            event->data.log.records,
                            event->tag,
                            event->tag != NULL ? flb_sds_len(event->tag) : 0,
                            event->data.log.buf,
                            event->data.log.size);
            }
            else {
                result = flb_input_log_append(
                            ins,
                            event->tag,
                            event->tag != NULL ? flb_sds_len(event->tag) : 0,
                            event->data.log.buf,
                            event->data.log.size);
            }
        }
        else if (event->type == FLB_INPUT_INGRESS_METRICS) {
            if (event->metrics_resume == FLB_TRUE) {
                metrics_context = cfl_list_entry(event->metrics.next, struct cmt, _head);
                result = flb_input_metrics_append_skip_processor_stages(
                             ins, event->metrics_starting_stage,
                             event->tag,
                             event->tag != NULL ? flb_sds_len(event->tag) : 0,
                             metrics_context);
            }
            else {
                result = flb_input_metrics_append_list(
                             ins,
                             event->tag,
                             event->tag != NULL ? flb_sds_len(event->tag) : 0,
                             &event->metrics);
            }
        }
        else if (event->type == FLB_INPUT_INGRESS_TRACES) {
            result = flb_input_trace_append(ins,
                                            event->tag,
                                            event->tag != NULL ? flb_sds_len(event->tag) : 0,
                                            event->data.traces);

            if (result == 0) {
                event->data.traces = NULL;
            }
        }
        else if (event->type == FLB_INPUT_INGRESS_PROFILES) {
            result = flb_input_profiles_append(ins,
                                               event->tag,
                                               event->tag != NULL ? flb_sds_len(event->tag) : 0,
                                               event->data.profiles);
        }
        else if (event->type == FLB_INPUT_INGRESS_RAW) {
            raw_events++;
            raw_bytes += event->size;

            if (ins->context != NULL && ins->p->cb_ingest != NULL) {
                result = ins->p->cb_ingest(ins, ins->context, &event->data.raw.view);
            }
            else {
                result = -1;
            }

            /* The plugin reports its own processing errors. A request that
             * got no reply is settled here so its caller never waits. */
            flb_input_ingest_event_settle(event, FLB_INPUT_INGEST_REPLY_FAILED);
            if (result != 0) {
                flb_debug("[input %s] external payload was not fully processed",
                          flb_input_name(ins));
                result = 0;
            }
        }
        else {
            result = -1;
        }


        pthread_mutex_lock(&ins->ingress_queue_lock);
        ins->ingress_queue_pending_events--;
        ins->ingress_queue_pending_bytes -= event->size;
        flb_input_ingress_update_metrics(ins);
        pthread_cond_broadcast(&ins->ingress_queue_space_available);
        pthread_mutex_unlock(&ins->ingress_queue_lock);
        flb_input_ingress_event_destroy(event);
        if (result != 0) {
            flb_error("[input %s] could not ingest deferred worker payload",
                      flb_input_name(ins));
        }
    }
    return 0;
}

int flb_input_ingress_enable(struct flb_input_instance *ins)
{
    int result;

    if (ins == NULL) {
        return -1;
    }

    if (ins->rb != NULL && ins->rb->event_loop == NULL) {
        result = flb_ring_buffer_add_event_loop(ins->rb,
                                                ins->config->evl,
                                                ins->ring_buffer_window);
        if (result != 0) {
            return -1;
        }
    }

    if (ins->ingress_queue_enabled == FLB_TRUE) {
        return 0;
    }

    if (ins->http_server_config != NULL) {
        ins->ingress_queue_event_limit =
            ins->http_server_config->ingress_queue_event_limit;

        if (ins->http_server_config->ingress_queue_byte_limit > 0) {
            ins->ingress_queue_byte_limit =
                ins->http_server_config->ingress_queue_byte_limit;
        }
        else {
            ins->ingress_queue_byte_limit = ins->mem_buf_limit;
        }
    }

    if (ins->mem_buf_limit > 0 &&
        (ins->ingress_queue_byte_limit == 0 ||
         ins->mem_buf_limit < ins->ingress_queue_byte_limit)) {
        ins->ingress_queue_byte_limit = ins->mem_buf_limit;
    }

    result = flb_pipe_create(ins->ingress_queue_channels);
    if (result != 0) {
        return -1;
    }

    flb_pipe_set_nonblocking(ins->ingress_queue_channels[0]);
    flb_pipe_set_nonblocking(ins->ingress_queue_channels[1]);

    ins->ingress_queue_collector_id = flb_input_set_collector_event(
                                        ins,
                                        flb_input_ingress_collector,
                                        ins->ingress_queue_channels[0],
                                        ins->config);
    if (ins->ingress_queue_collector_id < 0) {
        flb_pipe_destroy(ins->ingress_queue_channels);
        ins->ingress_queue_channels[0] = -1;
        ins->ingress_queue_channels[1] = -1;
        return -1;
    }

    ins->ingress_queue_enabled = FLB_TRUE;

    return 0;
}

void flb_input_ingress_destroy(struct flb_input_instance *ins)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_input_ingress_event *event;

    if (ins == NULL) {
        return;
    }

    pthread_mutex_lock(&ins->ingress_queue_lock);
    ins->ingress_queue_enabled = FLB_FALSE;
    ins->ingress_queue_signal_pending = FLB_FALSE;
    pthread_cond_broadcast(&ins->ingress_queue_space_available);
    mk_list_foreach_safe(head, tmp, &ins->ingress_queue) {
        event = mk_list_entry(head, struct flb_input_ingress_event, _head);
        flb_input_ingress_event_destroy(event);
    }
    ins->ingress_queue_pending_events = 0;
    ins->ingress_queue_pending_bytes = 0;
    flb_input_ingress_update_metrics(ins);
    pthread_mutex_unlock(&ins->ingress_queue_lock);
}

int flb_input_ingress_queue_log(struct flb_input_instance *ins,
                                const char *tag,
                                size_t tag_len,
                                const void *buf,
                                size_t buf_size)
{
    struct flb_input_ingress_event *event;

    if (buf == NULL || buf_size == 0) {
        return -1;
    }

    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_LOG, tag, tag_len);
    if (event == NULL) {
        return -1;
    }

    event->data.log.buf = flb_malloc(buf_size);
    if (event->data.log.buf == NULL) {
        flb_errno();
        flb_input_ingress_event_destroy(event);
        return -1;
    }

    memcpy(event->data.log.buf, buf, buf_size);
    event->data.log.size = buf_size;
    event->size = buf_size;

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_log_take(struct flb_input_instance *ins,
                                     const char *tag,
                                     size_t tag_len,
                                     void *buf,
                                     size_t buf_size,
                                     size_t allocation_size)
{
    return flb_input_ingress_queue_log_take_records(ins,
                                                    0,
                                                    tag,
                                                    tag_len,
                                                    buf,
                                                    buf_size,
                                                    allocation_size);
}

static int flb_input_ingress_queue_log_take_internal(struct flb_input_instance *ins,
                                                     size_t records,
                                                     int processed,
                                                     const char *tag,
                                                     size_t tag_len,
                                                     void *buf,
                                                     size_t buf_size,
                                                     size_t allocation_size)
{
    struct flb_input_ingress_event *event;

    if (buf == NULL || buf_size == 0) {
        if (buf != NULL) {
            flb_free(buf);
        }
        return -1;
    }

    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_LOG, tag, tag_len);
    if (event == NULL) {
        flb_free(buf);
        return -1;
    }

    event->data.log.buf = buf;
    event->data.log.size = buf_size;
    event->data.log.records = records;
    event->data.log.processed = processed;
    if (allocation_size < buf_size) {
        allocation_size = buf_size;
    }
    event->size = allocation_size;

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_log_take_records(struct flb_input_instance *ins,
                                             size_t records,
                                             const char *tag,
                                             size_t tag_len,
                                             void *buf,
                                             size_t buf_size,
                                             size_t allocation_size)
{
    return flb_input_ingress_queue_log_take_internal(ins, records, FLB_FALSE,
                                                     tag, tag_len, buf, buf_size,
                                                     allocation_size);
}

int flb_input_ingress_queue_log_processed_take_records(
                                             struct flb_input_instance *ins,
                                             size_t records,
                                             const char *tag,
                                             size_t tag_len,
                                             void *buf,
                                             size_t buf_size,
                                             size_t allocation_size)
{
    return flb_input_ingress_queue_log_take_internal(ins, records, FLB_TRUE,
                                                     tag, tag_len, buf, buf_size,
                                                     allocation_size);
}

int flb_input_ingress_queue_metrics(struct flb_input_instance *ins,
                                    const char *tag,
                                    size_t tag_len,
                                    struct cmt *cmt,
                                    size_t payload_size)
{
    struct flb_input_ingress_event *event;

    if (cmt == NULL) {
        return -1;
    }

    /* The ingress queue consumes 'cmt' on every return path. */
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_METRICS, tag, tag_len);
    if (event == NULL) {
        cmt_destroy(cmt);
        return -1;
    }

    if (!cfl_list_entry_is_orphan(&cmt->_head)) {
        cfl_list_del(&cmt->_head);
    }
    cfl_list_add(&cmt->_head, &event->metrics);
    event->size = flb_input_ingress_signal_size(payload_size);

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_metrics_list(struct flb_input_instance *ins,
                                         const char *tag,
                                         size_t tag_len,
                                         struct cfl_list *contexts,
                                         size_t payload_size)
{
    struct cfl_list *iterator;
    struct cfl_list *tmp;
    struct cmt *context;
    struct flb_input_ingress_event *event;

    if (contexts == NULL || cfl_list_is_empty(contexts)) {
        return -1;
    }

    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_METRICS,
                                           tag, tag_len);
    if (event == NULL) {
        cfl_list_foreach_safe(iterator, tmp, contexts) {
            context = cfl_list_entry(iterator, struct cmt, _head);
            cfl_list_del(&context->_head);
            cmt_destroy(context);
        }
        return -1;
    }

    cfl_list_foreach_safe(iterator, tmp, contexts) {
        context = cfl_list_entry(iterator, struct cmt, _head);
        cfl_list_del(&context->_head);
        cfl_list_add(&context->_head, &event->metrics);
    }
    event->size = flb_input_ingress_signal_size(payload_size);

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_traces(struct flb_input_instance *ins,
                                   const char *tag,
                                   size_t tag_len,
                                   struct ctrace *ctr,
                                   size_t payload_size)
{
    struct flb_input_ingress_event *event;

    if (ctr == NULL) {
        return -1;
    }

    /* The ingress queue consumes 'ctr' on every return path. */
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_TRACES, tag, tag_len);
    if (event == NULL) {
        ctr_destroy(ctr);
        return -1;
    }

    event->data.traces = ctr;
    event->size = flb_input_ingress_signal_size(payload_size);

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_profiles(struct flb_input_instance *ins,
                                     const char *tag,
                                     size_t tag_len,
                                     struct cprof *profile,
                                     size_t payload_size)
{
    struct flb_input_ingress_event *event;

    if (profile == NULL) {
        return -1;
    }

    /* The ingress queue consumes 'profile' on every return path. */
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_PROFILES, tag, tag_len);
    if (event == NULL) {
        cprof_destroy(profile);
        return -1;
    }

    event->data.profiles = profile;
    event->size = flb_input_ingress_signal_size(payload_size);

    return flb_input_ingress_enqueue(ins, event);
}

/*
 * Host-driven ingestion
 * =====================
 */

static void flb_input_ingest_event_settle(struct flb_input_ingress_event *event,
                                          int outcome)
{
    if (event->type != FLB_INPUT_INGRESS_RAW ||
        event->data.raw.replied == FLB_TRUE) {
        return;
    }

    event->data.raw.replied = FLB_TRUE;

    if (event->data.raw.reply_cb != NULL) {
        event->data.raw.reply_cb(outcome, NULL, event->data.raw.reply_data);
    }
}

int flb_input_ingest_event_reply(const struct flb_input_ingest_event *view,
                                 const struct flb_input_ingest_reply *reply)
{
    struct flb_input_ingress_event *event;

    if (view == NULL || view->priv == NULL || reply == NULL) {
        return -1;
    }

    event = view->priv;
    if (event->data.raw.replied == FLB_TRUE) {
        return -1;
    }

    event->data.raw.replied = FLB_TRUE;

    if (event->data.raw.reply_cb != NULL) {
        event->data.raw.reply_cb(FLB_INPUT_INGEST_REPLIED, reply,
                                 event->data.raw.reply_data);
    }

    return 0;
}

/* Take every queued host payload out of the queue. Call with the lock held. */
static void flb_input_ingest_detach_queued(struct flb_input_instance *ins,
                                           struct mk_list *detached)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_input_ingress_event *event;

    mk_list_foreach_safe(head, tmp, &ins->ingress_queue) {
        event = mk_list_entry(head, struct flb_input_ingress_event, _head);
        if (event->type != FLB_INPUT_INGRESS_RAW) {
            continue;
        }

        mk_list_del(&event->_head);
        mk_list_add(&event->_head, detached);
        ins->ingress_queue_pending_events--;
        ins->ingress_queue_pending_bytes -= event->size;
    }

    flb_input_ingress_update_metrics(ins);
    pthread_cond_broadcast(&ins->ingress_queue_space_available);
}

/* Settle and release detached payloads. Call without the lock held. */
static void flb_input_ingest_discard(struct mk_list *detached, int outcome)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_input_ingress_event *event;

    mk_list_foreach_safe(head, tmp, detached) {
        event = mk_list_entry(head, struct flb_input_ingress_event, _head);
        flb_input_ingest_event_settle(event, outcome);
        flb_input_ingress_event_destroy(event);
    }
}

void flb_input_ingest_fail(struct flb_input_instance *ins)
{
    struct mk_list detached;

    /* Only an instance in external mode can hold host payloads */
    if (ins == NULL || !flb_input_is_external(ins)) {
        return;
    }

    mk_list_init(&detached);

    pthread_mutex_lock(&ins->ingress_queue_lock);
    ins->ingest_failed = FLB_TRUE;
    flb_input_ingest_detach_queued(ins, &detached);
    pthread_mutex_unlock(&ins->ingress_queue_lock);

    flb_input_ingest_discard(&detached, FLB_INPUT_INGEST_REPLY_FAILED);
}

void flb_input_ingest_close(struct flb_input_instance *ins)
{
    struct mk_list detached;

    /* Only an instance in external mode can hold host payloads */
    if (ins == NULL || !flb_input_is_external(ins)) {
        return;
    }

    mk_list_init(&detached);

    pthread_mutex_lock(&ins->ingress_queue_lock);
    ins->ingest_closed = FLB_TRUE;
    flb_input_ingest_detach_queued(ins, &detached);
    pthread_mutex_unlock(&ins->ingress_queue_lock);

    flb_input_ingest_discard(&detached, FLB_INPUT_INGEST_REPLY_CANCELLED);
}

int flb_input_ingest_enable(struct flb_input_instance *ins)
{
    int result;

    result = flb_input_ingress_enable(ins);
    if (result != 0) {
        return -1;
    }

    /* The queue holds unparsed host payloads: keep it small */
    pthread_mutex_lock(&ins->ingress_queue_lock);
    if (ins->ingress_queue_byte_limit == 0 ||
        ins->ingress_queue_byte_limit > FLB_INPUT_INGEST_QUEUE_BYTE_LIMIT) {
        ins->ingress_queue_byte_limit = FLB_INPUT_INGEST_QUEUE_BYTE_LIMIT;
    }
    pthread_mutex_unlock(&ins->ingress_queue_lock);

    return 0;
}

/* Bytes needed after the envelope to hold a complete copy of the payload */
static int flb_input_ingest_storage_size(const void *data, size_t size,
                                         const struct flb_input_ingest_request *request,
                                         size_t *out_size)
{
    size_t i;
    size_t total;
    const struct flb_input_ingest_header *header;

    if (data == NULL && size > 0) {
        return FLB_INPUT_INGEST_ERROR;
    }

    if (size > FLB_INPUT_INGEST_EVENT_MAX) {
        return FLB_INPUT_INGEST_TOO_LARGE;
    }

    /* Every string gets a terminator */
    total = size + 1;

    if (request != NULL) {
        if ((request->method == NULL && request->method_len > 0) ||
            (request->path == NULL && request->path_len > 0) ||
            (request->headers == NULL && request->header_count > 0)) {
            return -1;
        }

        if (request->header_count > FLB_INPUT_INGEST_HEADER_MAX ||
            request->method_len > FLB_INPUT_INGEST_EVENT_MAX ||
            request->path_len > FLB_INPUT_INGEST_EVENT_MAX) {
            return FLB_INPUT_INGEST_TOO_LARGE;
        }

        total += request->method_len + 1 + request->path_len + 1;
        total += request->header_count * sizeof(struct flb_input_ingest_header);

        for (i = 0; i < request->header_count; i++) {
            header = &request->headers[i];

            if ((header->name == NULL && header->name_len > 0) ||
                (header->value == NULL && header->value_len > 0)) {
                return -1;
            }

            if (header->name_len > FLB_INPUT_INGEST_EVENT_MAX ||
                header->value_len > FLB_INPUT_INGEST_EVENT_MAX) {
                return FLB_INPUT_INGEST_TOO_LARGE;
            }

            total += header->name_len + 1 + header->value_len + 1;

            if (total > FLB_INPUT_INGEST_EVENT_MAX * 2) {
                return FLB_INPUT_INGEST_TOO_LARGE;
            }
        }
    }

    *out_size = total;

    return 0;
}

static char *flb_input_ingest_copy(char **cursor, const char *data, size_t size)
{
    char *start;

    start = *cursor;
    if (size > 0) {
        memcpy(start, data, size);
    }
    start[size] = '\0';
    *cursor = start + size + 1;

    return start;
}

static struct flb_input_ingress_event *flb_input_ingest_event_create(
    int kind,
    const void *data, size_t size,
    const struct flb_input_ingest_request *request,
    size_t storage_size)
{
    size_t i;
    size_t envelope;
    char *cursor;
    struct flb_input_ingest_header *headers;
    struct flb_input_ingress_event *event;
    struct flb_input_ingest_event *view;

    /* Keep the header array aligned right after the envelope */
    envelope = sizeof(struct flb_input_ingress_event);

    event = flb_calloc(1, envelope + storage_size);
    if (event == NULL) {
        flb_errno();
        return NULL;
    }

    event->type = FLB_INPUT_INGRESS_RAW;
    event->size = envelope + storage_size;
    cfl_list_init(&event->metrics);
    mk_list_entry_init(&event->_head);

    view = &event->data.raw.view;
    view->kind = kind;
    view->priv = event;

    cursor = ((char *) event) + envelope;

    if (request != NULL) {
        headers = (struct flb_input_ingest_header *) cursor;
        cursor += request->header_count * sizeof(struct flb_input_ingest_header);

        view->method = flb_input_ingest_copy(&cursor, request->method,
                                             request->method_len);
        view->method_len = request->method_len;
        view->path = flb_input_ingest_copy(&cursor, request->path, request->path_len);
        view->path_len = request->path_len;

        for (i = 0; i < request->header_count; i++) {
            headers[i].name = flb_input_ingest_copy(&cursor,
                                                    request->headers[i].name,
                                                    request->headers[i].name_len);
            headers[i].name_len = request->headers[i].name_len;
            headers[i].value = flb_input_ingest_copy(&cursor,
                                                     request->headers[i].value,
                                                     request->headers[i].value_len);
            headers[i].value_len = request->headers[i].value_len;
        }

        view->headers = headers;
        view->header_count = request->header_count;
    }

    view->data = flb_input_ingest_copy(&cursor, data, size);
    view->size = size;

    return event;
}

int flb_input_ingest_submit(struct flb_input_instance *ins,
                            int kind,
                            const void *data, size_t size,
                            const struct flb_input_ingest_request *request,
                            flb_input_ingest_reply_cb reply_cb,
                            void *reply_data)
{
    int result;
    int should_signal;
    size_t storage_size;
    size_t event_size;
    struct flb_input_ingress_event *event;

    if (ins == NULL || ins->p == NULL) {
        return FLB_INPUT_INGEST_ERROR;
    }

    if (kind != FLB_INPUT_INGEST_STREAM_BYTES &&
        kind != FLB_INPUT_INGEST_HTTP_REQUEST) {
        return FLB_INPUT_INGEST_ERROR;
    }

    if ((kind == FLB_INPUT_INGEST_HTTP_REQUEST) != (request != NULL)) {
        return FLB_INPUT_INGEST_ERROR;
    }

    if (!flb_input_is_external(ins) || ins->p->cb_ingest == NULL ||
        (ins->p->ingest_kinds & kind) == 0) {
        return FLB_INPUT_INGEST_NOT_SUPPORTED;
    }

    storage_size = 0;
    result = flb_input_ingest_storage_size(data, size, request, &storage_size);
    if (result != 0) {
        return result;
    }

    /* The limit covers the complete representation: body and context */
    if (storage_size > FLB_INPUT_INGEST_EVENT_MAX + 1) {
        return FLB_INPUT_INGEST_TOO_LARGE;
    }

    event_size = sizeof(struct flb_input_ingress_event) + storage_size;

    /* Check for room before copying anything; the answer is immediate */
    pthread_mutex_lock(&ins->ingress_queue_lock);
    result = FLB_INPUT_INGEST_OK;
    if (ins->ingest_closed == FLB_TRUE || ins->ingress_queue_enabled != FLB_TRUE) {
        result = FLB_INPUT_INGEST_NOT_RUNNING;
    }
    else if (ins->ingest_failed == FLB_TRUE) {
        result = FLB_INPUT_INGEST_FAILED;
    }
    else if (ins->ingress_queue_byte_limit > 0 &&
             event_size > ins->ingress_queue_byte_limit) {
        result = FLB_INPUT_INGEST_TOO_LARGE;
    }
    else if ((ins->ingress_queue_event_limit > 0 &&
              ins->ingress_queue_pending_events >= ins->ingress_queue_event_limit) ||
             (ins->ingress_queue_byte_limit > 0 &&
              ins->ingress_queue_pending_bytes >
                  ins->ingress_queue_byte_limit - event_size)) {
        result = FLB_INPUT_INGEST_BUSY;
    }
    pthread_mutex_unlock(&ins->ingress_queue_lock);

    if (result != FLB_INPUT_INGEST_OK) {
        return result;
    }

    event = flb_input_ingest_event_create(kind, data, size, request, storage_size);
    if (event == NULL) {
        return FLB_INPUT_INGEST_ERROR;
    }
    event->data.raw.reply_cb = reply_cb;
    event->data.raw.reply_data = reply_data;

    /* Another producer may have taken the room while copying */
    pthread_mutex_lock(&ins->ingress_queue_lock);
    if (ins->ingest_closed == FLB_TRUE || ins->ingress_queue_enabled != FLB_TRUE) {
        result = FLB_INPUT_INGEST_NOT_RUNNING;
    }
    else if (ins->ingest_failed == FLB_TRUE) {
        result = FLB_INPUT_INGEST_FAILED;
    }
    else if ((ins->ingress_queue_event_limit > 0 &&
              ins->ingress_queue_pending_events >= ins->ingress_queue_event_limit) ||
             (ins->ingress_queue_byte_limit > 0 &&
              ins->ingress_queue_pending_bytes >
                  ins->ingress_queue_byte_limit - event_size)) {
        result = FLB_INPUT_INGEST_BUSY;
    }

    if (result != FLB_INPUT_INGEST_OK) {
        pthread_mutex_unlock(&ins->ingress_queue_lock);
        /* Not admitted: no reply is owed */
        event->data.raw.replied = FLB_TRUE;
        flb_input_ingress_event_destroy(event);
        return result;
    }

    mk_list_add(&event->_head, &ins->ingress_queue);
    ins->ingress_queue_pending_events++;
    ins->ingress_queue_pending_bytes += event_size;
    flb_input_ingress_update_metrics(ins);
    should_signal = ins->ingress_queue_signal_pending == FLB_FALSE;
    ins->ingress_queue_signal_pending = FLB_TRUE;
    pthread_mutex_unlock(&ins->ingress_queue_lock);

    if (should_signal) {
        flb_input_ingress_signal(ins);
    }

    return FLB_INPUT_INGEST_OK;
}
