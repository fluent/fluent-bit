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

/*
 * Metrics interface is a helper to gather general metrics from the core or
 * plugins at runtime.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_metrics.h>
#include <msgpack.h>

static int id_exists(int id, struct flb_metrics *metrics)
{
    struct mk_list *head;
    struct flb_metric *metric;

    mk_list_foreach(head, &metrics->list) {
        metric = mk_list_entry(head, struct flb_metric, _head);
        if (metric->id == id) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int id_get(struct flb_metrics *metrics)
{
    int id;
    int ret = FLB_FALSE;

    /* Try to use 'count' as an id */
    id = metrics->count;

    while ((ret = id_exists(id, metrics)) == FLB_TRUE) {
        id++;
    }

    return id;
}

struct flb_metric *flb_metrics_get_id(int id, struct flb_metrics *metrics)
{
    struct mk_list *head;
    struct flb_metric *m;

    mk_list_foreach(head, &metrics->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        if (m->id == id) {
            return m;
        }
    }

    return NULL;
}

struct flb_metrics *flb_metrics_create(char *title)
{
    int ret;
    struct flb_metrics *metrics;

    metrics = flb_malloc(sizeof(struct flb_metrics));
    if (!metrics) {
        flb_errno();
        return NULL;
    }
    metrics->count = 0;

    ret = snprintf(metrics->title, sizeof(metrics->title) - 1, "%s", title);
    if (ret == -1) {
        flb_errno();
        flb_free(metrics);
        return NULL;
    }
    metrics->title_len = strlen(metrics->title);

    mk_list_init(&metrics->list);
    return metrics;
}

int flb_metrics_add(int id, char *title, struct flb_metrics *metrics)
{
    int ret;
    struct flb_metric *m;

    /* Create context */
    m = flb_malloc(sizeof(struct flb_metric));
    if (!m) {
        flb_errno();
        return -1;
    }
    m->val = 0;

    /* Write title */
    ret = snprintf(m->title, sizeof(m->title) - 1, "%s", title);
    if (ret == -1) {
        flb_errno();
        flb_free(m);
        return -1;
    }
    m->title_len = strlen(m->title);

    /* Assign an ID */
    if (id >= 0) {
        /* Check this new ID is available */
        if (id_exists(id, metrics) == FLB_TRUE) {
            flb_error("[metrics] id=%i already exists for metric '%s'",
                      id, metrics->title);
            flb_free(m);
            return -1;
        }
    }
    else {
        id = id_get(metrics);
    }

    /* Link to parent list */
    mk_list_add(&m->_head, &metrics->list);
    m->id = id;
    metrics->count++;

    return id;
}

int flb_metrics_sum(int id, size_t val, struct flb_metrics *metrics)
{
    struct flb_metric *m;

    m = flb_metrics_get_id(id, metrics);
    if (!m) {
        return -1;
    }

    m->val += val;
    return 0;
}

int flb_metrics_destroy(struct flb_metrics *metrics)
{
    int count = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_metric *m;

    mk_list_foreach_safe(head, tmp, &metrics->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        mk_list_del(&m->_head);
        flb_free(m);
        count++;
    }

    flb_free(metrics);
    return count;
}

int flb_metrics_print(struct flb_metrics *metrics)
{
    struct mk_list *head;
    struct flb_metric *m;

    printf("[metric dump] title => '%s'", metrics->title);

    mk_list_foreach(head, &metrics->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        printf(", '%s' => %lu", m->title, m->val);
    }
    printf("\n");

    return 0;
}

/* Write metrics in messagepack format */
int flb_metrics_dump_values(char **out_buf, size_t *out_size,
                            struct flb_metrics *me)
{
    struct mk_list *head;
    struct flb_metric *m;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, me->count);

    mk_list_foreach(head, &me->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        msgpack_pack_str(&mp_pck, m->title_len);
        msgpack_pack_str_body(&mp_pck, m->title, m->title_len);
        msgpack_pack_uint64(&mp_pck, m->val);
    }

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}
