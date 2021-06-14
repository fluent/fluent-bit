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

/*
 * Prometheus Exposition Format
 * ----------------------------
 * https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md
 */

void sds_cat_safe(cmt_sds_t *buf, const char *str, int len)
{
    cmt_sds_t tmp;

    tmp = cmt_sds_cat(*buf, str, len);
    if (!tmp) {
        return;
    }
    *buf = tmp;
}

static void metric_banner(cmt_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    struct cmt_opts *opts;

    opts = map->opts;

    /* HELP */
    sds_cat_safe(buf, "# HELP ", 7);
    sds_cat_safe(buf, opts->fqname, cmt_sds_len(opts->fqname));

    sds_cat_safe(buf, " ", 1);
    sds_cat_safe(buf, opts->description, cmt_sds_len(opts->description));
    sds_cat_safe(buf, "\n", 1);

    /* TYPE */
    sds_cat_safe(buf, "# TYPE ", 7);
    sds_cat_safe(buf, opts->fqname, cmt_sds_len(opts->fqname));

    if (map->type == CMT_COUNTER) {
        sds_cat_safe(buf, " counter\n", 9);
    }
    else if (map->type == CMT_GAUGE) {
        sds_cat_safe(buf, " gauge\n", 7);
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
    sds_cat_safe(buf, tmp, len);
}

static void format_metric(cmt_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric, int add_timestamp)
{
    int i;
    int n;
    double val;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct mk_list *head;
    struct cmt_opts *opts;

    opts = map->opts;

    /* Metric info */
    sds_cat_safe(buf, opts->fqname, cmt_sds_len(opts->fqname));

    n = mk_list_size(&metric->labels);
    if (n > 0) {
        sds_cat_safe(buf, "{", 1);

        label_k = mk_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        i = 1;
        mk_list_foreach(head, &metric->labels) {
            label_v = mk_list_entry(head, struct cmt_map_label, _head);

            sds_cat_safe(buf, label_k->name, cmt_sds_len(label_k->name));
            sds_cat_safe(buf, "=\"", 2);
            sds_cat_safe(buf, label_v->name, cmt_sds_len(label_v->name));

            if (i < n) {
                sds_cat_safe(buf, "\",", 2);
            }
            else {
                sds_cat_safe(buf, "\"", 1);
            }
            i++;

            label_k = mk_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
        }
        sds_cat_safe(buf, "}", 1);

        append_metric_value(buf, metric, add_timestamp);
    }
    else {
        append_metric_value(buf, metric, add_timestamp);
    }
}

void format_metrics(cmt_sds_t *buf, struct cmt_map *map, int add_timestamp)
{
    struct mk_list *head;
    struct cmt_metric *metric;

    /* Simple metric, no labels */
    if (map->metric_static_set == 1) {
        metric_banner(buf, map, &map->metric);
        format_metric(buf, map, &map->metric, add_timestamp);
        return;
    }

    if (mk_list_size(&map->metrics) > 0) {
        metric = mk_list_entry_first(&map->metrics, struct cmt_metric, _head);
        metric_banner(buf, map, metric);
    }

    mk_list_foreach(head, &map->metrics) {
        metric = mk_list_entry(head, struct cmt_metric, _head);
        format_metric(buf, map, metric, add_timestamp);
    }
}

/* Format all the registered metrics in Prometheus Text format */
cmt_sds_t cmt_encode_prometheus_create(struct cmt *cmt, int add_timestamp)
{
    cmt_sds_t buf;
    struct mk_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;

    /* Allocate a 1KB of buffer */
    buf = cmt_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    /* Counters */
    mk_list_foreach(head, &cmt->counters) {
        counter = mk_list_entry(head, struct cmt_counter, _head);
        format_metrics(&buf, counter->map, add_timestamp);
    }

    /* Gauges */
    mk_list_foreach(head, &cmt->gauges) {
        gauge = mk_list_entry(head, struct cmt_gauge, _head);
        format_metrics(&buf, gauge->map, add_timestamp);
    }

    return buf;
}

void cmt_encode_prometheus_destroy(cmt_sds_t text)
{
    cmt_sds_destroy(text);
}
