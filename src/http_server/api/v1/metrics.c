/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <fluent-bit/flb_http_server.h>
#include <msgpack.h>

pthread_key_t hs_metrics_key;

struct flb_hs_buf *get_metrics()
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
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list;
    struct flb_hs_buf *last;
    struct flb_hs_buf *entry;

    metrics_list = pthread_getspecific(hs_metrics_key);
    if (!metrics_list) {
        return -1;
    }

    last = get_metrics();
    if (!last) {
        return -1;
    }

    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct flb_hs_buf, _head);
        if (entry != last && entry->users == 0) {
            mk_list_del(&entry->_head);
            flb_free(entry->data);
            flb_free(entry);
        }
    }
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
    mk_list_add(&buf->_head, metrics_list);

    cleanup_metrics();
}

/* API: expose built-in metrics */
static void cb_metrics(mk_request_t *request, void *data)
{
    struct flb_hs_buf *buf;

    buf = get_metrics();
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

    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/metrics", cb_metrics, hs);
    return 0;
}
