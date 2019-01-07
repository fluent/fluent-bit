/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

#include <fluent-bit/flb_http_server.h>
#include <msgpack.h>

#define _BSD_SOURCE

#include <sys/time.h>

#define PROMETHEUS_HEADER "text/plain; version=0.0.4"

pthread_key_t hs_metrics_key;

/* Return the newest metrics buffer */
static struct flb_hs_buf *metrics_get_latest()
{
    struct flb_hs_buf *buf;
    struct mk_list *metrics_list;

    metrics_list = pthread_getspecific(hs_metrics_key);
    if (!metrics_list) {
        return NULL;
    }

    if (mk_list_size(metrics_list) == 0) {
        return NULL;
    }

    buf = mk_list_entry_last(metrics_list, struct flb_hs_buf, _head);
    return buf;
}

/* Delete unused metrics, note that we only care about the latest node */
int cleanup_metrics()
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list;
    struct flb_hs_buf *last;
    struct flb_hs_buf *entry;

    metrics_list = pthread_getspecific(hs_metrics_key);
    if (!metrics_list) {
        return -1;
    }

    last = metrics_get_latest();
    if (!last) {
        return -1;
    }

    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct flb_hs_buf, _head);
        if (entry != last && entry->users == 0) {
            mk_list_del(&entry->_head);
            flb_free(entry->data);
            flb_free(entry->raw_data);
            flb_free(entry);
            c++;
        }
    }

    return c;
}

/*
 * Callback invoked every time some metrics are received through a
 * message queue channel. This function runs in a Monkey HTTP thread
 * worker and it purpose is to take the metrics data and store it
 * somewhere so then it can be available by the end-points upon
 * HTTP client requests.
 */
static void cb_mq_metrics(mk_mq_t *queue, void *data, size_t size)
{
    int ret;
    char *json_buf;
    size_t json_size;
    struct flb_hs_buf *buf;
    struct mk_list *metrics_list = NULL;

    metrics_list = pthread_getspecific(hs_metrics_key);
    if (!metrics_list) {
        metrics_list = flb_malloc(sizeof(struct mk_list));
        if (!metrics_list) {
            flb_errno();
            return;
        }
        mk_list_init(metrics_list);
        pthread_setspecific(hs_metrics_key, metrics_list);
    }

    /* Convert msgpack to JSON */
    ret = flb_msgpack_raw_to_json_str(data, size, &json_buf, &json_size);
    if (ret < 0) {
        return;
    }

    buf = flb_malloc(sizeof(struct flb_hs_buf));
    if (!buf) {
        flb_errno();
        return;
    }
    buf->users = 0;
    buf->data = json_buf;
    buf->size = json_size;

    buf->raw_data = flb_malloc(size);
    memcpy(buf->raw_data, data, size);
    buf->raw_size = size;

    mk_list_add(&buf->_head, metrics_list);

    cleanup_metrics();
}

/* API: expose metrics in Prometheus format /api/v1/metrics/prometheus */
void cb_metrics_prometheus(mk_request_t *request, void *data)
{
    int i;
    int j;
    int m;
    int len;
    int time_len;
    long now;
    flb_sds_t sds;
    size_t off = 0;
    struct flb_hs_buf *buf;
    msgpack_unpacked result;
    msgpack_object map;
    char tmp[32];
    char time_str[64];
    struct timeval tp;

    buf = metrics_get_latest();
    if (!buf) {
        mk_http_status(request, 404);
        mk_http_done(request);
        return;
    }

    /* ref count */
    buf->users++;

    /* Compose outgoing buffer string */
    sds = flb_sds_create_size(1024);
    if (!sds) {
        mk_http_status(request, 500);
        mk_http_done(request);
        buf->users--;
        return;
    }

    /* current time */
    gettimeofday(&tp, NULL);
    now = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    time_len = snprintf(time_str, sizeof(time_str) - 1, "%lu", now);

    /*
     * fluentbit_input_records[name="cpu0", hostname="${HOSTNAME}"] NUM TIMESTAMP
     * fluentbit_input_bytes[name="cpu0", hostname="${HOSTNAME}"] NUM TIMESTAMP
     */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf->raw_data, buf->raw_size, &off);
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

                sds = flb_sds_cat(sds, "fluentbit_", 10);
                sds = flb_sds_cat(sds, (char *) k.via.str.ptr, k.via.str.size);
                sds = flb_sds_cat(sds, "_", 1);
                sds = flb_sds_cat(sds, (char *) mk.via.str.ptr, mk.via.str.size);
                sds = flb_sds_cat(sds, "_total{name=\"", 13);
                sds = flb_sds_cat(sds, (char *) sk.via.str.ptr, sk.via.str.size);
                sds = flb_sds_cat(sds, "\"} ", 3);

                len = snprintf(tmp, sizeof(tmp) - 1,
                               "%" PRIu64 " ", mv.via.u64);
                sds = flb_sds_cat(sds, tmp, len);
                sds = flb_sds_cat(sds, time_str, time_len);
                sds = flb_sds_cat(sds, "\n", 1);
            }
        }
    }
    msgpack_unpacked_destroy(&result);
    buf->users--;

    mk_http_status(request, 200);
    mk_http_header(request,
                   "Content-Type", 12,
                   PROMETHEUS_HEADER, sizeof(PROMETHEUS_HEADER) - 1);
    mk_http_send(request, sds, flb_sds_len(sds), NULL);
    mk_http_done(request);
    flb_sds_destroy(sds);
}

/* API: expose built-in metrics /api/v1/metrics */
static void cb_metrics(mk_request_t *request, void *data)
{
    struct flb_hs_buf *buf;

    buf = metrics_get_latest();
    if (!buf) {
        mk_http_status(request, 404);
        mk_http_done(request);
        return;
    }

    buf->users++;

    mk_http_status(request, 200);
    mk_http_send(request, buf->data, buf->size, NULL);
    mk_http_done(request);

    buf->users--;
}

/* Perform registration */
int api_v1_metrics(struct flb_hs *hs)
{

    pthread_key_create(&hs_metrics_key, NULL);

    /* Create a message queue */
    hs->qid = mk_mq_create(hs->ctx, "/metrics", cb_mq_metrics, NULL);

    /* HTTP end-points */
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/metrics/prometheus",
                     cb_metrics_prometheus, hs);
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/metrics", cb_metrics, hs);

    return 0;
}
