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

#include<stdio.h>
#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_server.h>
#include <msgpack.h>

#include "health.h"

struct flb_hs_throughput_state throughput_check_state = {0};

struct flb_health_check_metrics_counter *metrics_counter;

pthread_key_t hs_health_key;

static struct flb_hs_throughput_sample *samples_add(
        struct flb_hs_throughput_samples *samples)
{
    struct flb_hs_throughput_sample *sample = samples->items + samples->insert;
    samples->insert = (samples->insert + 1) % samples->size;
    if (samples->count < samples->size) {
        samples->count++;
    }
    return sample;
}

static int samples_translate_index(
        struct flb_hs_throughput_samples *samples, int index)
{
    if (index >= samples->count || index < 0) {
        return -1;
    }
    int end_index = samples->insert;
    int start_index = end_index - samples->count;
    int modulo = (start_index + index) % samples->size;
    return modulo < 0 ? modulo + samples->size : modulo;
}

static struct flb_hs_throughput_sample *samples_get(
        struct flb_hs_throughput_samples *samples, int index)
{
    int real_index = samples_translate_index(samples, index);
    if (real_index < 0) {
        return NULL;
    }

    return samples->items + real_index;
}


static struct mk_list *hs_health_key_create()
{
    struct mk_list *metrics_list = NULL;

    metrics_list = flb_malloc(sizeof(struct mk_list));
    if (!metrics_list) {
        flb_errno();
        return NULL;
    }
    mk_list_init(metrics_list);
    pthread_setspecific(hs_health_key, metrics_list);

    return metrics_list;
}

static void hs_health_key_destroy(void *data)
{
    struct mk_list *metrics_list = (struct mk_list*)data;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hs_hc_buf *entry;

    if (metrics_list == NULL) {
        return;
    }
    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct flb_hs_hc_buf, _head);
        if (entry != NULL) {
            mk_list_del(&entry->_head);
            flb_free(entry);
        }
    }

    flb_free(metrics_list);
}

/* initialize the metrics counters */
static void counter_init(struct flb_hs *hs) {

   metrics_counter = flb_malloc(sizeof(struct flb_health_check_metrics_counter));

   if (!metrics_counter) {
       flb_errno();
       return;
   }

    metrics_counter->error_counter = 0;
    metrics_counter->retry_failure_counter = 0;
    metrics_counter->error_limit = hs->config->hc_errors_count;
    metrics_counter->retry_failure_limit = hs->config->hc_retry_failure_count;
    metrics_counter->period_counter = 0;
    metrics_counter->period_limit = hs->config->health_check_period;

}

static bool contains_str(struct mk_list *items, msgpack_object_str name)
{
    struct mk_list *head;
    struct flb_split_entry *entry;

    if (!items) {
        return false;
    }

    mk_list_foreach(head, items) {
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        if (!strncmp(name.ptr, entry->value, name.size)) {
            return true;
        }
    }

    return false;
}

/*
* tell what's the current status for health check
* One default background is that the metrics received and saved into
* message queue every time is a accumulation of error numbers,
* not a error number in recent second. So to get the error number
* in a period, we need to use:
* the error number of the newest metrics message  minus
* the error number in oldest metrics of period
*/
static int is_healthy() {

    struct mk_list *metrics_list;
    struct flb_hs_hc_buf *buf;
    int period_errors;
    int period_retry_failure;

    metrics_list = pthread_getspecific(hs_health_key);
    if (metrics_list == NULL) {
        metrics_list = hs_health_key_create();
        if (metrics_list == NULL) {
            return FLB_FALSE;
        }
    }

    if (mk_list_is_empty(metrics_list) == 0) {
        return FLB_TRUE && throughput_check_state.healthy;
    }

    /* Get the error metrics entry from the start time of current period */
    buf = mk_list_entry_first(metrics_list, struct flb_hs_hc_buf, _head);

    /*
    * increase user so clean up function won't
    * free the memory and delete the data
    */
    buf->users++;

    /* the error count saved in message queue is the number of
    * error count at that time. So the math is that:
    * the error count in current period = (current error count in total) -
    * (begin error count in the period)
    */
    period_errors = metrics_counter->error_counter -  buf->error_count;
    period_retry_failure = metrics_counter->retry_failure_counter -
                                                buf->retry_failure_count;
    buf->users--;

    if (period_errors > metrics_counter->error_limit ||
        period_retry_failure >  metrics_counter->retry_failure_limit) {

        return FLB_FALSE;
    }

    return FLB_TRUE && throughput_check_state.healthy;
}

/* read the metrics from message queue and update the counter*/
static void read_metrics(void *data,
                         size_t size,
                         struct mk_list *input_plugins,
                         struct mk_list *output_plugins,
                         int* error_count,
                         int* retry_failure_count,
                         uint64_t *input_records,
                         uint64_t *output_records)
{
    int i;
    int j;
    int m;
    msgpack_unpacked result;
    msgpack_object map;
    size_t off = 0;
    int errors = 0;
    int retry_failure = 0;
    uint64_t in_recs = 0;
    uint64_t out_recs = 0;

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, data, size, &off);
    map = result.data;

    for (i = 0; i < map.via.map.size; i++) {
        msgpack_object k;
        msgpack_object v;

        /* Keys: input, output */
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;

        /* Iterate sub-map */
        for (j = 0; j < v.via.map.size; j++) {
            msgpack_object sk;
            msgpack_object sv;

            /* Keys: plugin name , values: metrics */
            sk = v.via.map.ptr[j].key;
            sv = v.via.map.ptr[j].val;

            for (m = 0; m < sv.via.map.size; m++) {
                msgpack_object mk;
                msgpack_object mv;

                mk = sv.via.map.ptr[m].key;
                mv = sv.via.map.ptr[m].val;

                if (!strncmp(k.via.str.ptr, "output", k.via.str.size)) {
                    if (!strncmp(mk.via.str.ptr, "errors", mk.via.str.size)) {
                        errors += mv.via.u64;
                    }
                    else if (!strncmp(mk.via.str.ptr, "retries_failed", mk.via.str.size)) {
                        retry_failure += mv.via.u64;
                    }
                    else if (!strncmp(mk.via.str.ptr, "proc_records", mk.via.str.size) &&
                              contains_str(output_plugins, sk.via.str)) {
                        out_recs += mv.via.u64;
                    }
                }

                if (!strncmp(k.via.str.ptr, "input", k.via.str.size) &&
                    !strncmp(mk.via.str.ptr, "records", mk.via.str.size) &&
                    contains_str(input_plugins, sk.via.str)) {
                    in_recs += mv.via.u64;
                }
            }
        }
    }

    *error_count = errors;
    *retry_failure_count = retry_failure;
    *input_records = in_recs;
    *output_records = out_recs;
    msgpack_unpacked_destroy(&result);
}

/*
* Delete unused metrics, note that we only care about the latest node
* we use this function to maintain the metrics queue only save the metrics
* in a period. The old metrics which is out of period will be removed
*/
static int cleanup_metrics()
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list;
    struct flb_hs_hc_buf *entry;

    metrics_list = pthread_getspecific(hs_health_key);
    if (!metrics_list) {
        return -1;
    }

    if (metrics_counter->period_counter < metrics_counter->period_limit) {
        return 0;
    }

    /* remove the oldest metrics if it's out of period */
    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct flb_hs_hc_buf, _head);
        if (metrics_counter->period_counter > metrics_counter->period_limit &&
                entry->users == 0) {
            metrics_counter->period_counter--;
            mk_list_del(&entry->_head);
            flb_free(entry);
            c++;
        }
        else {
            break;
        }
    }

    return c;
}

static int check_throughput_health(uint64_t in_records,
                                   uint64_t out_records,
                                   struct flb_hs_throughput_samples *samples,
                                   double out_in_ratio_threshold) {
    int i;
    struct flb_time tp;
    uint64_t in_rate;
    uint64_t out_rate;
    double out_in_ratio;
    struct flb_hs_throughput_sample *entry;
    struct flb_hs_throughput_sample *prev;
    struct flb_hs_throughput_sample *sample;
    bool healthy;
    bool rv;

    flb_time_get(&tp);

    sample = samples_add(samples);
    sample->timestamp_seconds = flb_time_to_seconds(&tp);
    sample->in_records = in_records;
    sample->out_records = out_records;

    flb_debug("[api/v1/health/throughput]: check samples start %d %f",
              samples->size,
              out_in_ratio_threshold);

    healthy = false;
    for (i = samples->count - 1; i > 0; i--) {
        entry = samples_get(samples, i);
        prev = samples_get(samples, i - 1);
        uint64_t timestamp_delta = entry->timestamp_seconds - prev->timestamp_seconds;
        if (timestamp_delta == 0) {
            /* check against divide by zero */
            continue;
        }
        in_rate = (entry->in_records - prev->in_records) / timestamp_delta;
        out_rate = (entry->out_records - prev->out_records) / timestamp_delta;
        out_in_ratio = (double)out_rate / (double)in_rate;
        healthy = healthy || out_in_ratio > out_in_ratio_threshold;

        flb_debug("[api/v1/health/throughput]: out: %"PRIu64" in: %"PRIu64" ratio: %f",
                  out_in_ratio,
                  out_rate,
                  in_rate);

        if (healthy) {
            break;
        }
    }

    rv = samples->count < samples->size || healthy;
    flb_debug("checking throughput samples stop, result: %s",
              rv ? "healthy" :"unhealthy");

    return rv;
}


/*
 * Callback invoked every time some metrics are received through a
 * message queue channel. This function runs in a Monkey HTTP thread
 * worker and it purpose is to take the metrics data and record the health
 * status based on the metrics.
 * This happens every second based on the event config.
 * So we treat period_counter to count the time.
 * And we maintain a message queue with the size of period limit number
 * so every time we get a new metrics data in, if the message queue size is
 * large than period limit, we will do the clean up func to
 * remove the oldest metrics.
 */
static void cb_mq_health(mk_mq_t *queue, void *data, size_t size)
{
    struct flb_hs_hc_buf *buf;
    struct mk_list *metrics_list = NULL;
    int error_count = 0;
    int retry_failure_count = 0;
    uint64_t input_records = 0;
    uint64_t output_records = 0;

    metrics_list = pthread_getspecific(hs_health_key);

    if (metrics_list == NULL) {
        metrics_list = hs_health_key_create();
        if (metrics_list == NULL) {
            return;
        }
    }

    metrics_counter->period_counter++;

    /* this is to remove the metrics out of period*/
    cleanup_metrics();

    buf = flb_malloc(sizeof(struct flb_hs_hc_buf));
    if (!buf) {
        flb_errno();
        return;
    }

    buf->users = 0;

    read_metrics(data,
                 size,
                 throughput_check_state.input_plugins,
                 throughput_check_state.output_plugins,
                 &error_count,
                 &retry_failure_count,
                 &input_records,
                 &output_records);


    if (throughput_check_state.enabled) {
        throughput_check_state.healthy =
            check_throughput_health(input_records,
                                    output_records,
                                    &throughput_check_state.samples,
                                    throughput_check_state.out_in_ratio_threshold);
    }

    metrics_counter->error_counter = error_count;
    metrics_counter->retry_failure_counter = retry_failure_count;

    buf->error_count = error_count;
    buf->retry_failure_count = retry_failure_count;

    mk_list_add(&buf->_head, metrics_list);
}

/* API: Get fluent Bit Health Status */
static void cb_health(mk_request_t *request, void *data)
{
    int status = is_healthy();

    if (status == FLB_TRUE) {
       mk_http_status(request, 200);
       mk_http_send(request, "ok\n", strlen("ok\n"), NULL);
       mk_http_done(request);
    }
    else {
        mk_http_status(request, 500);
        mk_http_send(request, "error\n", strlen("error\n"), NULL);
        mk_http_done(request);
    }
}

static void configure_throughput_check(struct flb_config *config)
{
    bool enabled = config->hc_throughput;

    memset(&throughput_check_state, 0, sizeof(throughput_check_state));
    throughput_check_state.enabled = false;
    throughput_check_state.healthy = true;

    if (!enabled) {
        return;
    }

    if (!config->hc_throughput_input_plugins) {
        flb_warn("[api/v1/health/throughput]: " FLB_CONF_STR_HC_THROUGHPUT_IN_PLUGINS " is required");
        return;
    }
    if (!config->hc_throughput_output_plugins) {
        flb_warn("[api/v1/health/throughput]: " FLB_CONF_STR_HC_THROUGHPUT_OUT_PLUGINS " is required");
        return;
    }
    if (!config->hc_throughput_ratio_threshold) {
        flb_warn("[api/v1/health/throughput]: " FLB_CONF_STR_HC_THROUGHPUT_RATIO_THRESHOLD " is required");
        return;
    }
    if (!config->hc_throughput_min_failures) {
        flb_warn("[api/v1/health/throughput]: " FLB_CONF_STR_HC_THROUGHPUT_MIN_FAILURES " is required");
        return;
    }

    throughput_check_state.input_plugins =
        flb_utils_split(config->hc_throughput_input_plugins, ',', 0);

    if (!throughput_check_state.input_plugins) {
        flb_errno();
        return;
    }

    throughput_check_state.output_plugins =
        flb_utils_split(config->hc_throughput_output_plugins, ',', 0);

    if (!throughput_check_state.output_plugins) {
        flb_free(throughput_check_state.input_plugins);
        flb_errno();
        return;
    }

    throughput_check_state.out_in_ratio_threshold = config->hc_throughput_ratio_threshold;
    throughput_check_state.enabled = true;

    throughput_check_state.samples.items = flb_calloc(
            config->hc_throughput_min_failures,
            sizeof(struct flb_hs_throughput_sample));

    if (!throughput_check_state.samples.items) {
        flb_free(throughput_check_state.input_plugins);
        flb_free(throughput_check_state.output_plugins);
        flb_errno();
        return;
    }
    throughput_check_state.samples.size = config->hc_throughput_min_failures;

    flb_info("[api/v1/health/throughput]: configuration complete. "
             "input plugins: %s | "
             "output plugins: %s | "
             "ratio threshold: %f | "
             "min failures: %d",
              config->hc_throughput_input_plugins,
              config->hc_throughput_output_plugins,
              config->hc_throughput_ratio_threshold,
              config->hc_throughput_min_failures);
}

/* Perform registration */
int api_v1_health(struct flb_hs *hs)
{
    configure_throughput_check(hs->config);

    pthread_key_create(&hs_health_key, hs_health_key_destroy);

    counter_init(hs);
    /* Create a message queue */
    hs->qid_health = mk_mq_create(hs->ctx, "/health",
                                   cb_mq_health, NULL);

    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/health", cb_health, hs);
    return 0;
}

void flb_hs_health_destroy()
{
    flb_free(metrics_counter);
}
