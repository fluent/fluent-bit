/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include "prom_metrics.h"

pthread_key_t prom_metrics_key;

static int cleanup_metrics();

struct prom_metrics_buf *prom_metrics_get_latest()
{
    struct prom_metrics_buf *buf;
    struct mk_list *metrics_list;

    metrics_list = pthread_getspecific(prom_metrics_key);
    if (!metrics_list) {
        return NULL;
    }

    if (mk_list_size(metrics_list) == 0) {
        return NULL;
    }

    buf = mk_list_entry_last(metrics_list, struct prom_metrics_buf, _head);
    return buf;
}

/* Delete unused metrics, note that we only care about the latest node */
static int cleanup_metrics()
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list;
    struct prom_metrics_buf *last;
    struct prom_metrics_buf *entry;

    metrics_list = pthread_getspecific(prom_metrics_key);
    if (!metrics_list) {
        return -1;
    }

    last = prom_metrics_get_latest();
    if (!last) {
        return -1;
    }

    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct prom_metrics_buf, _head);
        if (entry != last && entry->users == 0) {
            mk_list_del(&entry->_head);
            flb_free(entry->buf_data);
            flb_free(entry);
            c++;
        }
    }

    return c;
}

int prom_metrics_push_new_metrics(void *data, size_t size)
{
    struct prom_metrics_buf *buf;
    struct mk_list *metrics_list = NULL;

    metrics_list = pthread_getspecific(prom_metrics_key);
    if (!metrics_list) {
        metrics_list = flb_malloc(sizeof(struct mk_list));
        if (!metrics_list) {
            return -1;
        }
        mk_list_init(metrics_list);
        pthread_setspecific(prom_metrics_key, metrics_list);
    }

    buf = flb_malloc(sizeof(struct prom_metrics_buf));
    if (!buf) {
        return -1;
    }

    buf->users = 0;
    buf->buf_data = flb_malloc(size);
    if (!buf->buf_data) {
        flb_free(buf);
        return -1;
    }
    memcpy(buf->buf_data, data, size);
    buf->buf_size = size;

    mk_list_add(&buf->_head, metrics_list);
    return cleanup_metrics();
}

void prom_metrics_destroy_metrics()
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list;
    struct prom_metrics_buf *entry;

    metrics_list = pthread_getspecific(prom_metrics_key);
    if (!metrics_list) {
        return;
    }

    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct prom_metrics_buf, _head);
        mk_list_del(&entry->_head);
        flb_free(entry->buf_data);
        flb_free(entry);
    }

    flb_free(metrics_list);
}
