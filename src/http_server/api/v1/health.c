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
#include <fluent-bit/flb_http_server.h>
#include <msgpack.h>

#include "health.h"

struct flb_health_check_metrics_counter *metrics_counter;

pthread_key_t hs_health_key;

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
        return FLB_TRUE;
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

    return FLB_TRUE;
}

/* read the metrics from message queue and update the counter*/
static void read_metrics(void *data, size_t size, int* error_count,
                         int* retry_failure_count)
{
    int i;
    int j;
    int m;
    msgpack_unpacked result;
    msgpack_object map;
    size_t off = 0;
    int errors = 0;
    int retry_failure = 0;

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, data, size, &off);
    map = result.data;

    for (i = 0; i < map.via.map.size; i++) {
        msgpack_object k;
        msgpack_object v;

        /* Keys: input, output */
        k = map.via.map.ptr[i].key;
        v = map.via.map.ptr[i].val;
        if (k.via.str.size != sizeof("output") - 1 ||
            strncmp(k.via.str.ptr, "output", k.via.str.size) != 0) {

            continue;
        }
        /* Iterate sub-map */
        for (j = 0; j < v.via.map.size; j++) {
            msgpack_object sv;

            /* Keys: plugin name , values: metrics */
            sv = v.via.map.ptr[j].val;

            for (m = 0; m < sv.via.map.size; m++) {
                msgpack_object mk;
                msgpack_object mv;

                mk = sv.via.map.ptr[m].key;
                mv = sv.via.map.ptr[m].val;

                if (mk.via.str.size == sizeof("errors") - 1 &&
                    strncmp(mk.via.str.ptr, "errors", mk.via.str.size) == 0) {
                    errors += mv.via.u64;
                }
                else if (mk.via.str.size == sizeof("retries_failed") - 1 &&
                    strncmp(mk.via.str.ptr, "retries_failed",
                            mk.via.str.size) == 0) {
                    retry_failure += mv.via.u64;
                }
            }
        }
    }

    *error_count = errors;
    *retry_failure_count = retry_failure;
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

    read_metrics(data, size, &error_count, &retry_failure_count);

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

/* Perform registration */
int api_v1_health(struct flb_hs *hs)
{

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
