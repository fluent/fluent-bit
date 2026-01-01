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
#include <fluent-bit/flb_sds.h>
#include "storage.h"

#include <fluent-bit/flb_http_server.h>
#include <msgpack.h>

pthread_key_t hs_storage_metrics_key;

/* Return the newest storage metrics buffer */
static struct flb_hs_buf *storage_metrics_get_latest()
{
    struct flb_hs_buf *buf;
    struct mk_list *metrics_list;

    metrics_list = pthread_getspecific(hs_storage_metrics_key);
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

    metrics_list = pthread_getspecific(hs_storage_metrics_key);
    if (!metrics_list) {
        return -1;
    }

    last = storage_metrics_get_latest();
    if (!last) {
        return -1;
    }

    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct flb_hs_buf, _head);
        if (entry != last && entry->users == 0) {
            mk_list_del(&entry->_head);
            flb_sds_destroy(entry->data);
            flb_free(entry->raw_data);
            flb_free(entry);
            c++;
        }
    }

    return c;
}

/*
 * Callback invoked every time some storage metrics are received through a
 * message queue channel. This function runs in a Monkey HTTP thread
 * worker and it purpose is to take the metrics data and store it
 * somewhere so then it can be available by the end-points upon
 * HTTP client requests.
 */
static void cb_mq_storage_metrics(mk_mq_t *queue, void *data, size_t size)
{
    flb_sds_t out_data;
    struct flb_hs_buf *buf;
    struct mk_list *metrics_list = NULL;

    metrics_list = pthread_getspecific(hs_storage_metrics_key);
    if (!metrics_list) {
        metrics_list = flb_malloc(sizeof(struct mk_list));
        if (!metrics_list) {
            flb_errno();
            return;
        }
        mk_list_init(metrics_list);
        pthread_setspecific(hs_storage_metrics_key, metrics_list);
    }

    /* Convert msgpack to JSON */
    out_data = flb_msgpack_raw_to_json_sds(data, size, FLB_TRUE);
    if (!out_data) {
        return;
    }

    buf = flb_malloc(sizeof(struct flb_hs_buf));
    if (!buf) {
        flb_errno();
        flb_sds_destroy(out_data);
        return;
    }
    buf->users = 0;
    buf->data = out_data;

    buf->raw_data = flb_malloc(size);
    memcpy(buf->raw_data, data, size);
    buf->raw_size = size;

    mk_list_add(&buf->_head, metrics_list);

    cleanup_metrics();
}

/* FIXME: pending implementation of metrics exit interface
static void cb_mq_storage_metrics_exit(mk_mq_t *queue, void *data)
{

}
*/

/* API: expose built-in storage metrics /api/v1/storage */
static void cb_storage(mk_request_t *request, void *data)
{
    struct flb_hs_buf *buf;

    buf = storage_metrics_get_latest();
    if (!buf) {
        mk_http_status(request, 404);
        mk_http_done(request);
        return;
    }

    buf->users++;

    mk_http_status(request, 200);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_JSON);
    mk_http_send(request, buf->data, flb_sds_len(buf->data), NULL);
    mk_http_done(request);

    buf->users--;
}

static void hs_storage_metrics_key_destroy(void *data)
{
    struct mk_list *metrics_list = (struct mk_list*)data;
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
                flb_free(entry->raw_data);
                entry->raw_data = NULL;
            }
            if (entry->data) {
                flb_sds_destroy(entry->data);
                entry->data = NULL;
            }
            mk_list_del(&entry->_head);
            flb_free(entry);
        }
    }

    flb_free(metrics_list);
}

/* Perform registration */
int api_v1_storage_metrics(struct flb_hs *hs)
{
    pthread_key_create(&hs_storage_metrics_key, hs_storage_metrics_key_destroy);

    /* Create a message queue */
    hs->qid_storage = mk_mq_create(hs->ctx, "/storage",
                                   cb_mq_storage_metrics,
                                   NULL);

    /* HTTP end-point */
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/storage", cb_storage, hs);

    return 0;
}
