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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_time.h>
#include "metrics.h"

#include <fluent-bit/flb_http_server.h>

#define null_check(x) do { if (!x) { goto error; } else {sds = x;} } while (0)

pthread_key_t hs_metrics_v2_key;

static struct mk_list *hs_metrics_v2_key_create()
{
    struct mk_list *metrics_list = NULL;

    metrics_list = flb_malloc(sizeof(struct mk_list));
    if (metrics_list == NULL) {
        flb_errno();
        return NULL;
    }
    mk_list_init(metrics_list);
    pthread_setspecific(hs_metrics_v2_key, metrics_list);

    return metrics_list;
}

static void hs_metrics_v2_key_destroy(void *data)
{
    struct mk_list *metrics_list = (struct mk_list*) data;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hs_buf *entry;

    if (metrics_list == NULL) {
        return;
    }
    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct flb_hs_buf, _head);
        if (entry != NULL) {
            if (entry->raw_data != NULL) {
                cmt_destroy(entry->raw_data);
                entry->raw_data = NULL;
            }
            mk_list_del(&entry->_head);
            flb_free(entry);
        }
    }

    flb_free(metrics_list);
}

/* Return the newest metrics buffer */
static struct flb_hs_buf *metrics_get_latest()
{
    struct flb_hs_buf *buf;
    struct mk_list *metrics_list;

    metrics_list = pthread_getspecific(hs_metrics_v2_key);
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
static int cleanup_metrics()
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list;
    struct flb_hs_buf *last;
    struct flb_hs_buf *entry;

    metrics_list = pthread_getspecific(hs_metrics_v2_key);
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
            cmt_destroy(entry->raw_data);
            flb_free(entry);
            c++;
        }
    }

    return c;
}

/*
 * Callback invoked every time some metrics are received through a message queue channel.
 * This function runs in a Monkey HTTP thread worker and it purpose is to take the metrics
 * data and store it somewhere so then it can be available by the end-points upon
 * HTTP client requests.
 */
static void cb_mq_metrics(mk_mq_t *queue, void *data, size_t size)
{
    int ret;
    size_t off = 0;
    struct cmt *cmt;
    struct flb_hs_buf *buf;
    struct mk_list *metrics_list = NULL;

    metrics_list = pthread_getspecific(hs_metrics_v2_key);
    if (!metrics_list) {
        metrics_list = hs_metrics_v2_key_create();
        if (metrics_list == NULL) {
            return;
        }
    }

    /* decode cmetrics */
    ret = cmt_decode_msgpack_create(&cmt, data, size, &off);
    if (ret != 0) {
        return;
    }

    buf = flb_malloc(sizeof(struct flb_hs_buf));
    if (!buf) {
        flb_errno();
        return;
    }
    buf->users = 0;
    buf->data = NULL;

    /* Store CMetrics context as the raw_data */
    buf->raw_data = cmt;
    buf->raw_size = 0;

    mk_list_add(&buf->_head, metrics_list);
    cleanup_metrics();
}

/* API: expose metrics in Prometheus format /api/v2/metrics/prometheus */
static void cb_metrics_prometheus(mk_request_t *request, void *data)
{
    struct cmt *cmt;
    struct flb_hs_buf *buf;
    cfl_sds_t payload;

    buf = metrics_get_latest();
    if (!buf) {
        mk_http_status(request, 404);
        mk_http_done(request);
        return;
    }

    cmt = (struct cmt *) buf->raw_data;

    /* convert CMetrics to text */
    payload = cmt_encode_prometheus_create(cmt, CMT_FALSE);
    if (!payload) {
        mk_http_status(request, 500);
        mk_http_done(request);
        return;
    }

    buf->users++;

    mk_http_status(request, 200);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_PROMETHEUS);
    mk_http_send(request, payload, cfl_sds_len(payload), NULL);
    mk_http_done(request);

    cmt_encode_prometheus_destroy(payload);

    buf->users--;
}

/* API: expose built-in metrics /api/v1/metrics (JSON format) */
static void cb_metrics(mk_request_t *request, void *data)
{
    struct cmt *cmt;
    struct flb_hs_buf *buf;
    cfl_sds_t payload;

    buf = metrics_get_latest();
    if (!buf) {
        mk_http_status(request, 404);
        mk_http_done(request);
        return;
    }

    cmt = (struct cmt *) buf->raw_data;

    /* convert CMetrics to text */
    payload = cmt_encode_text_create(cmt);
    if (!payload) {
        mk_http_status(request, 500);
        mk_http_done(request);
        return;
    }

    buf->users++;

    mk_http_status(request, 200);
    mk_http_send(request, payload, cfl_sds_len(payload), NULL);
    mk_http_done(request);

    cmt_encode_text_destroy(payload);

    buf->users--;
}

/* Perform registration */
int api_v2_metrics(struct flb_hs *hs)
{

    pthread_key_create(&hs_metrics_v2_key, hs_metrics_v2_key_destroy);

    /* Create a message queue */
    hs->qid_metrics_v2 = mk_mq_create(hs->ctx, "/metrics_v2",
                                      cb_mq_metrics, NULL);
    /* HTTP end-points */
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v2/metrics/prometheus",
                     cb_metrics_prometheus, hs);

    mk_vhost_handler(hs->ctx, hs->vid, "/api/v2/metrics", cb_metrics, hs);

    return 0;
}
