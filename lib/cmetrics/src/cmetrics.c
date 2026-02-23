/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <stdlib.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_label.h>
#include <cmetrics/cmt_version.h>

#include <cfl/cfl_kvlist.h>

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

    cmt->internal_metadata = cfl_kvlist_create();

    if (cmt->internal_metadata == NULL) {
        cmt_labels_destroy(cmt->static_labels);

        free(cmt);
        return NULL;
    }

    cmt->external_metadata = cfl_kvlist_create();

    if (cmt->external_metadata == NULL) {
        cfl_kvlist_destroy(cmt->internal_metadata);
        cmt_labels_destroy(cmt->static_labels);

        free(cmt);
        return NULL;
    }

    cfl_list_init(&cmt->counters);
    cfl_list_init(&cmt->gauges);
    cfl_list_init(&cmt->histograms);
    cfl_list_init(&cmt->exp_histograms);
    cfl_list_init(&cmt->summaries);
    cfl_list_init(&cmt->untypeds);

    cmt->log_level = CMT_LOG_ERROR;

    cfl_list_entry_init(&cmt->_head);
    
    return cmt;
}

void cmt_destroy(struct cmt *cmt)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_summary *s;
    struct cmt_histogram *h;
    struct cmt_exp_histogram *eh;
    struct cmt_untyped *u;

    cfl_list_foreach_safe(head, tmp, &cmt->counters) {
        c = cfl_list_entry(head, struct cmt_counter, _head);
        cmt_counter_destroy(c);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->gauges) {
        g = cfl_list_entry(head, struct cmt_gauge, _head);
        cmt_gauge_destroy(g);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->summaries) {
        s = cfl_list_entry(head, struct cmt_summary, _head);
        cmt_summary_destroy(s);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->histograms) {
        h = cfl_list_entry(head, struct cmt_histogram, _head);
        cmt_histogram_destroy(h);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->exp_histograms) {
        eh = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        cmt_exp_histogram_destroy(eh);
    }

    cfl_list_foreach_safe(head, tmp, &cmt->untypeds) {
        u = cfl_list_entry(head, struct cmt_untyped, _head);
        cmt_untyped_destroy(u);
    }

    if (cmt->static_labels) {
        cmt_labels_destroy(cmt->static_labels);
    }

    if (cmt->internal_metadata != NULL) {
        cfl_kvlist_destroy(cmt->internal_metadata);
    }

    if (cmt->external_metadata != NULL) {
        cfl_kvlist_destroy(cmt->external_metadata);
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
