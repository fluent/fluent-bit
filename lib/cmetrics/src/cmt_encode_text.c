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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_time.h>
#include <cmetrics/cmt_compat.h>

static void append_histogram_metric_value(cfl_sds_t *buf,
                                          struct cmt_map *map,
                                          struct cmt_metric *metric)
{
    char                         *bucket_value_format_string;
    size_t                        entry_buffer_length;
    size_t                        entry_buffer_index;
    char                          entry_buffer[256];
    struct cmt_histogram         *histogram;
    struct cmt_histogram_buckets *buckets;
    size_t                        index;

    histogram = (struct cmt_histogram *) map->parent;
    buckets = histogram->buckets;

    cfl_sds_cat_safe(buf, " = { buckets = { ", 17);

    for (index = 0 ; index <= buckets->count ; index++) {
        if (index < buckets->count) {
            entry_buffer_index = snprintf(entry_buffer,
                                           sizeof(entry_buffer) - 1,
                                           "%g",
                                           buckets->upper_bounds[index]);

            bucket_value_format_string = "=%" PRIu64 ", ";
        }
        else {
            entry_buffer_index = snprintf(entry_buffer,
                                           sizeof(entry_buffer) - 1,
                                           "+Inf");

            bucket_value_format_string = "=%" PRIu64 " ";
        }

        entry_buffer_length = entry_buffer_index;

        entry_buffer_length += snprintf(&entry_buffer[entry_buffer_index],
                                        sizeof(entry_buffer) - 1 -
                                        entry_buffer_index,
                                        bucket_value_format_string,
                                        cmt_metric_hist_get_value(metric,
                                                                  index));

        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    cfl_sds_cat_safe(buf, "}, ", 3);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "sum=%g, ",
                                   cmt_metric_hist_get_sum_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "count=%" PRIu64 ,
                                   cmt_metric_hist_get_count_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    cfl_sds_cat_safe(buf, " }\n", 3);
}

static void append_summary_metric_value(cfl_sds_t *buf,
                                        struct cmt_map *map,
                                        struct cmt_metric *metric)
{
    char               *quantile_pair_format_string;
    size_t              entry_buffer_length;
    char                entry_buffer[256];
    struct cmt_summary *summary;
    size_t              index;

    summary = (struct cmt_summary *) map->parent;

    cfl_sds_cat_safe(buf, " = { quantiles = { ", 19);

    for (index = 0 ; index < summary->quantiles_count ; index++) {
        if (index < summary->quantiles_count - 1) {
            quantile_pair_format_string = "%g=%g, ";
        }
        else {
            quantile_pair_format_string = "%g=%g ";
        }

        entry_buffer_length = snprintf(entry_buffer,
                                       sizeof(entry_buffer) - 1,
                                       quantile_pair_format_string,
                                       summary->quantiles[index],
                                       cmt_summary_quantile_get_value(metric,
                                                                      index));

        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    cfl_sds_cat_safe(buf, "}, ", 3);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "sum=%g, ",
                                   cmt_summary_get_sum_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "count=%" PRIu64,
                                   cmt_summary_get_count_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    cfl_sds_cat_safe(buf, " }\n", 3);
}

static void append_metric_value(cfl_sds_t *buf, struct cmt_map *map,
                                struct cmt_metric *metric)
{
    int len;
    double val;
    char tmp[128];

    if (map->type == CMT_HISTOGRAM) {
        return append_histogram_metric_value(buf, map, metric);
    }
    else if (map->type == CMT_SUMMARY) {
        return append_summary_metric_value(buf, map, metric);
    }

    /* Retrieve metric value */
    val = cmt_metric_get_value(metric);

    len = snprintf(tmp, sizeof(tmp) - 1, " = %.17g\n", val);
    cfl_sds_cat_safe(buf, tmp, len);
}

static void format_metric(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    int i;
    int n;
    int len;
    int count = 0;
    int static_labels = 0;
    char tmp[128];
    uint64_t ts;
    struct tm tm;
    struct timespec tms;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct cfl_list *head;
    struct cmt_opts *opts;
    struct cmt_label *slabel;

    opts = map->opts;

    /* timestamp (RFC3339Nano) */
    ts = cmt_metric_get_timestamp(metric);

    cmt_time_from_ns(&tms, ts);

    cmt_platform_gmtime_r(&tms.tv_sec, &tm);
    len = strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H:%M:%S.", &tm);
    cfl_sds_cat_safe(buf, tmp, len);

    len = snprintf(tmp, sizeof(tmp) - 1, "%09luZ ", tms.tv_nsec);
    cfl_sds_cat_safe(buf, tmp, len);

    /* Metric info */
    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));

    /* Static labels */
    static_labels = cmt_labels_count(cmt->static_labels);
    if (static_labels > 0) {
        cfl_sds_cat_safe(buf, "{", 1);
        cfl_list_foreach(head, &cmt->static_labels->list) {
            count++;
            slabel = cfl_list_entry(head, struct cmt_label, _head);
            cfl_sds_cat_safe(buf, slabel->key, cfl_sds_len(slabel->key));
            cfl_sds_cat_safe(buf, "=\"", 2);
            cfl_sds_cat_safe(buf, slabel->val, cfl_sds_len(slabel->val));
            cfl_sds_cat_safe(buf, "\"", 1);

            if (count < static_labels) {
                cfl_sds_cat_safe(buf, ",", 1);
            }
        }
    }

    n = cfl_list_size(&metric->labels);
    if (n > 0) {
        if (static_labels > 0) {
            cfl_sds_cat_safe(buf, ",", 1);
        }
        else {
            cfl_sds_cat_safe(buf, "{", 1);
        }

        label_k = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        i = 1;
        cfl_list_foreach(head, &metric->labels) {
            label_v = cfl_list_entry(head, struct cmt_map_label, _head);

            cfl_sds_cat_safe(buf, label_k->name, cfl_sds_len(label_k->name));
            cfl_sds_cat_safe(buf, "=\"", 2);
            cfl_sds_cat_safe(buf, label_v->name, cfl_sds_len(label_v->name));

            if (i < n) {
                cfl_sds_cat_safe(buf, "\",", 2);
            }
            else {
                cfl_sds_cat_safe(buf, "\"", 1);
            }
            i++;

            label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
        }
        cfl_sds_cat_safe(buf, "}", 1);

        append_metric_value(buf, map, metric);
    }
    else {
        if (static_labels > 0) {
            cfl_sds_cat_safe(buf, "}", 1);
        }
        append_metric_value(buf, map, metric);
    }
}

static void format_metrics(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map)
{
    struct cfl_list *head;
    struct cmt_metric *metric;

    /* Simple metric, no labels */
    if (map->metric_static_set == 1) {
        format_metric(cmt, buf, map, &map->metric);
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        format_metric(cmt, buf, map, metric);
    }
}

/* Format all the registered metrics in Prometheus Text format */
cfl_sds_t cmt_encode_text_create(struct cmt *cmt)
{
    cfl_sds_t buf;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;

    /* Allocate a 1KB of buffer */
    buf = cfl_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        format_metrics(cmt, &buf, counter->map);
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        format_metrics(cmt, &buf, gauge->map);
    }

    /* Summaries */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        format_metrics(cmt, &buf, summary->map);
    }

    /* Histograms */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        format_metrics(cmt, &buf, histogram->map);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        format_metrics(cmt, &buf, untyped->map);
    }

    return buf;
}

void cmt_encode_text_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
