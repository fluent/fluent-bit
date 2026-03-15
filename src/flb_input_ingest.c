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

#include <cprofiles/cprof_encode_msgpack.h>

enum flb_input_ingress_event_type {
    FLB_INPUT_INGRESS_LOG = 0,
    FLB_INPUT_INGRESS_METRICS,
    FLB_INPUT_INGRESS_TRACES,
    FLB_INPUT_INGRESS_PROFILES
};

struct flb_input_ingress_event {
    int type;
    flb_sds_t tag;
    size_t size;

    union {
        struct {
            void   *buf;
            size_t  size;
        } log;
        struct cmt    *metrics;
        struct ctrace *traces;
        struct cprof  *profiles;
    } data;

    struct mk_list _head;
};

static void flb_input_ingress_event_destroy(struct flb_input_ingress_event *event)
{
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
        if (event->data.metrics != NULL) {
            cmt_destroy(event->data.metrics);
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

static size_t flb_input_ingress_estimate_metrics_size(struct cmt *cmt)
{
    if (cmt == NULL) {
        return 0;
    }

    /* Deferred worker ingress must not touch complex decoded signal objects
     * beyond ownership transfer. Conservative accounting is safer here than
     * re-encoding on the worker thread. 64 KiB is an intentionally coarse
     * upper-bound for typical decoded signal objects; tune it only after
     * profiling real workloads shows that this safety margin is too strict or
     * too loose for queue backpressure.
     */
    return 64 * 1024;
}

static size_t flb_input_ingress_estimate_traces_size(struct ctrace *ctr)
{
    if (ctr == NULL) {
        return 0;
    }

    /* Keep trace accounting aligned with the conservative signal estimate
     * used for metrics/profiles to avoid worker-side re-encoding.
     */
    return 64 * 1024;
}

static size_t flb_input_ingress_estimate_profiles_size(struct cprof *profile)
{
    if (profile == NULL) {
        return 0;
    }

    /* Keep profile accounting aligned with the conservative signal estimate
     * used for metrics/traces to avoid worker-side re-encoding.
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

    while (ins->ingress_queue_enabled == FLB_TRUE) {
        queue_is_full = FLB_FALSE;

        if (ins->ingress_queue_event_limit > 0 &&
            ins->ingress_queue_pending_events >= ins->ingress_queue_event_limit) {
            queue_is_full = FLB_TRUE;
        }

        if (ins->ingress_queue_byte_limit > 0 &&
            ins->ingress_queue_pending_bytes + event_size > ins->ingress_queue_byte_limit) {
            queue_is_full = FLB_TRUE;
        }

        if (queue_is_full == FLB_FALSE) {
            break;
        }

        clock_gettime(CLOCK_REALTIME, &deadline);
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

            flb_input_ingress_event_destroy(event);

            return FLB_INPUT_INGRESS_BUSY;
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
    int queue_was_full;
    size_t pending_events;
    size_t pending_bytes;
    struct mk_list *head;
    struct mk_list *tmp;
    struct mk_list queue;
    struct flb_input_ingress_event *event;

    (void) config;
    (void) context;

    mk_list_init(&queue);
    flb_input_ingress_drain_signal(ins);

    while (FLB_TRUE) {
        pthread_mutex_lock(&ins->ingress_queue_lock);

        if (mk_list_is_empty(&ins->ingress_queue) == 0) {
            ins->ingress_queue_signal_pending = FLB_FALSE;
            pthread_mutex_unlock(&ins->ingress_queue_lock);
            break;
        }

        pending_events = ins->ingress_queue_pending_events;
        pending_bytes = ins->ingress_queue_pending_bytes;
        queue_was_full = FLB_FALSE;

        if ((ins->ingress_queue_event_limit > 0 &&
             pending_events >= ins->ingress_queue_event_limit) ||
            (ins->ingress_queue_byte_limit > 0 &&
             pending_bytes >= ins->ingress_queue_byte_limit)) {
            queue_was_full = FLB_TRUE;
        }

        mk_list_foreach_safe(head, tmp, &ins->ingress_queue) {
            mk_list_del(head);
            mk_list_add(head, &queue);
        }

        ins->ingress_queue_pending_events = 0;
        ins->ingress_queue_pending_bytes = 0;
        ins->ingress_queue_signal_pending = FLB_FALSE;

        if (queue_was_full == FLB_TRUE) {
            pthread_cond_broadcast(&ins->ingress_queue_space_available);
        }

        pthread_mutex_unlock(&ins->ingress_queue_lock);

        mk_list_foreach_safe(head, tmp, &queue) {
            event = mk_list_entry(head, struct flb_input_ingress_event, _head);
            mk_list_del(head);
            mk_list_entry_init(&event->_head);

            if (event->type == FLB_INPUT_INGRESS_LOG) {
                result = flb_input_log_append(ins,
                                              event->tag,
                                              event->tag != NULL ? flb_sds_len(event->tag) : 0,
                                              event->data.log.buf,
                                              event->data.log.size);
            }
            else if (event->type == FLB_INPUT_INGRESS_METRICS) {
                result = flb_input_metrics_append(ins,
                                                  event->tag,
                                                  event->tag != NULL ? flb_sds_len(event->tag) : 0,
                                                  event->data.metrics);
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
            else {
                result = -1;
            }

            flb_input_ingress_event_destroy(event);

            if (result != 0) {
                flb_error("[input %s] could not ingest deferred worker payload",
                          flb_input_name(ins));
            }
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

    if (ins->mem_buf_limit > 0 &&
        ins->mem_buf_limit < ins->ingress_queue_byte_limit) {
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
    struct flb_input_ingress_event *event;

    if (buf == NULL || buf_size == 0) {
        return -1;
    }

    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_LOG, tag, tag_len);
    if (event == NULL) {
        flb_free(buf);
        return -1;
    }

    event->data.log.buf = buf;
    event->data.log.size = buf_size;
    if (allocation_size < buf_size) {
        allocation_size = buf_size;
    }
    event->size = allocation_size;

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_metrics(struct flb_input_instance *ins,
                                    const char *tag,
                                    size_t tag_len,
                                    struct cmt *cmt)
{
    struct flb_input_ingress_event *event;

    if (cmt == NULL) {
        return -1;
    }

    /* Ownership of 'cmt' is transferred to the ingress queue on success. */
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_METRICS, tag, tag_len);
    if (event == NULL) {
        return -1;
    }

    event->data.metrics = cmt;
    event->size = flb_input_ingress_estimate_metrics_size(cmt);

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_traces(struct flb_input_instance *ins,
                                   const char *tag,
                                   size_t tag_len,
                                   struct ctrace *ctr)
{
    struct flb_input_ingress_event *event;

    if (ctr == NULL) {
        return -1;
    }

    /* Ownership of 'ctr' is transferred to the ingress queue on success. */
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_TRACES, tag, tag_len);
    if (event == NULL) {
        return -1;
    }

    event->data.traces = ctr;
    event->size = flb_input_ingress_estimate_traces_size(ctr);

    return flb_input_ingress_enqueue(ins, event);
}

int flb_input_ingress_queue_profiles(struct flb_input_instance *ins,
                                     const char *tag,
                                     size_t tag_len,
                                     struct cprof *profile)
{
    struct flb_input_ingress_event *event;

    if (profile == NULL) {
        return -1;
    }

    /* Ownership of 'profile' is transferred to the ingress queue on success. */
    event = flb_input_ingress_event_create(FLB_INPUT_INGRESS_PROFILES, tag, tag_len);
    if (event == NULL) {
        return -1;
    }

    event->data.profiles = profile;
    event->size = flb_input_ingress_estimate_profiles_size(profile);

    return flb_input_ingress_enqueue(ins, event);
}
