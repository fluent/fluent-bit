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
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_sds.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_compat.h>

/*
 * Prometheus Exposition Format
 * ----------------------------
 * https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md
 */

static void metric_banner(cmt_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    struct cmt_opts *opts;

    opts = map->opts;

    /* HELP */
    cmt_sds_cat_safe(buf, "# HELP ", 7);
    cmt_sds_cat_safe(buf, opts->fqname, cmt_sds_len(opts->fqname));

    cmt_sds_cat_safe(buf, " ", 1);
    cmt_sds_cat_safe(buf, opts->description, cmt_sds_len(opts->description));
    cmt_sds_cat_safe(buf, "\n", 1);

    /* TYPE */
    cmt_sds_cat_safe(buf, "# TYPE ", 7);
    cmt_sds_cat_safe(buf, opts->fqname, cmt_sds_len(opts->fqname));

    if (map->type == CMT_COUNTER) {
        cmt_sds_cat_safe(buf, " counter\n", 9);
    }
    else if (map->type == CMT_GAUGE) {
        cmt_sds_cat_safe(buf, " gauge\n", 7);
    }
    else if (map->type == CMT_UNTYPED) {
        cmt_sds_cat_safe(buf, " untyped\n", 9);
    }
}

static void append_metric_value(cmt_sds_t *buf, struct cmt_metric *metric,
                                int add_timestamp)
{
    int len;
    double val;
    uint64_t ts;
    char tmp[128];

    /* Retrieve metric value */
    val = cmt_metric_get_value(metric);

    if (add_timestamp) {
        ts = cmt_metric_get_timestamp(metric);

        /* convert from nanoseconds to milliseconds */
        ts /= 1000000;

        len = snprintf(tmp, sizeof(tmp) - 1, " %.17g %" PRIu64 "\n", val, ts);
    }
    else {
        len = snprintf(tmp, sizeof(tmp) - 1, " %.17g\n", val);
    }
    cmt_sds_cat_safe(buf, tmp, len);
}

static void format_metric(struct cmt *cmt,
                          cmt_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric, int add_timestamp)
{
    int i;
    int n;
    int count = 0;
    int static_labels = 0;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct mk_list *head;
    struct cmt_opts *opts;
    struct cmt_label *slabel;

    opts = map->opts;

    /* Metric info */
    cmt_sds_cat_safe(buf, opts->fqname, cmt_sds_len(opts->fqname));

    /* Static labels */
    static_labels = cmt_labels_count(cmt->static_labels);
    if (static_labels > 0) {
        cmt_sds_cat_safe(buf, "{", 1);

        mk_list_foreach(head, &cmt->static_labels->list) {
            count++;
            slabel = mk_list_entry(head, struct cmt_label, _head);
            cmt_sds_cat_safe(buf, slabel->key, cmt_sds_len(slabel->key));
            cmt_sds_cat_safe(buf, "=\"", 2);
            cmt_sds_cat_safe(buf, slabel->val, cmt_sds_len(slabel->val));
            cmt_sds_cat_safe(buf, "\"", 1);

            if (count < static_labels) {
                cmt_sds_cat_safe(buf, ",", 1);
            }
        }
    }

    /* Append static labels */
    n = mk_list_size(&metric->labels);
    if (n > 0) {
        if (static_labels > 0) {
            cmt_sds_cat_safe(buf, ",", 1);
        }
        else {
            cmt_sds_cat_safe(buf, "{", 1);
        }

        label_k = mk_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        i = 1;
        mk_list_foreach(head, &metric->labels) {
            label_v = mk_list_entry(head, struct cmt_map_label, _head);

            cmt_sds_cat_safe(buf, label_k->name, cmt_sds_len(label_k->name));
            cmt_sds_cat_safe(buf, "=\"", 2);
            cmt_sds_cat_safe(buf, label_v->name, cmt_sds_len(label_v->name));

            if (i < n) {
                cmt_sds_cat_safe(buf, "\",", 2);
            }
            else {
                cmt_sds_cat_safe(buf, "\"", 1);
            }
            i++;

            label_k = mk_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
        }
        cmt_sds_cat_safe(buf, "}", 1);
        append_metric_value(buf, metric, add_timestamp);
    }
    else {
        if (static_labels > 0) {
            cmt_sds_cat_safe(buf, "}", 1);
        }
        append_metric_value(buf, metric, add_timestamp);
    }

}

static void format_metrics(struct cmt *cmt, cmt_sds_t *buf, struct cmt_map *map,
                           int add_timestamp)
{
    int banner_set = CMT_FALSE;
    struct mk_list *head;
    struct cmt_metric *metric;

    /* Simple metric, no labels */
    if (map->metric_static_set) {
        metric_banner(buf, map, &map->metric);
        banner_set = CMT_TRUE;
        format_metric(cmt, buf, map, &map->metric, add_timestamp);
    }

    if (mk_list_size(&map->metrics) > 0) {
        metric = mk_list_entry_first(&map->metrics, struct cmt_metric, _head);
        if (!banner_set) {
            metric_banner(buf, map, metric);
        }
    }

    mk_list_foreach(head, &map->metrics) {
        metric = mk_list_entry(head, struct cmt_metric, _head);
        format_metric(cmt, buf, map, metric, add_timestamp);
    }
}

/* Format all the registered metrics in Prometheus Text format */
cmt_sds_t cmt_encode_prometheus_create(struct cmt *cmt, int add_timestamp)
{
    cmt_sds_t buf;
    struct mk_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;

    /* Allocate a 1KB of buffer */
    buf = cmt_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    /* Counters */
    mk_list_foreach(head, &cmt->counters) {
        counter = mk_list_entry(head, struct cmt_counter, _head);
        format_metrics(cmt, &buf, counter->map, add_timestamp);
    }

    /* Gauges */
    mk_list_foreach(head, &cmt->gauges) {
        gauge = mk_list_entry(head, struct cmt_gauge, _head);
        format_metrics(cmt, &buf, gauge->map, add_timestamp);
    }

    /* Untyped */
    mk_list_foreach(head, &cmt->untypeds) {
        untyped = mk_list_entry(head, struct cmt_untyped, _head);
        format_metrics(cmt, &buf, untyped->map, add_timestamp);
    }

    return buf;
}

void cmt_encode_prometheus_destroy(cmt_sds_t text)
{
    cmt_sds_destroy(text);
}
