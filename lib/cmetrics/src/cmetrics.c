/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_label.h>
#include <cmetrics/cmt_version.h>

#include <stdlib.h>

void cmt_initialize()
{
    cmt_atomic_initialize();
}

struct cmt *cmt_create()
{
    struct cmt *cmt;

    cmt = calloc(1, sizeof(struct cmt));
    if (!cmt) {
        cmt_errno();
        return NULL;
    }

    cmt->static_labels = cmt_labels_create();
    if (!cmt->static_labels) {
        free(cmt);
        return NULL;
    }

    mk_list_init(&cmt->counters);
    mk_list_init(&cmt->gauges);
    mk_list_init(&cmt->histograms);

    return cmt;
}

void cmt_destroy(struct cmt *cmt)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cmt_gauge *g;
    struct cmt_counter *c;

    mk_list_foreach_safe(head, tmp, &cmt->gauges) {
        g = mk_list_entry(head, struct cmt_gauge, _head);
        cmt_gauge_destroy(g);
    }

    mk_list_foreach_safe(head, tmp, &cmt->counters) {
        c = mk_list_entry(head, struct cmt_counter, _head);
        cmt_counter_destroy(c);
    }

    if (cmt->static_labels) {
        cmt_labels_destroy(cmt->static_labels);
    }

    free(cmt);
}

int cmt_label_add(struct cmt *cmt, char *key, char *val)
{
    return cmt_labels_add_kv(cmt->static_labels, key, val);
}

char *cmt_version()
{
    return CMT_VERSION_STR;
}
