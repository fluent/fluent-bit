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
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_compat.h>

#include <ctype.h>

/*
 * Influx wire protocol
 * --------------------
 * https://docs.influxdata.com/influxdb/cloud/reference/syntax/line-protocol/
 *
 * Format used by influxdb when ingesting prometheus metrics
 * ---------------------------------------------------------
 * https://docs.influxdata.com/influxdb/v2.1/reference/prometheus-metrics/
 */


/* Histograms and Summaries :
 * Just to get started I'll use version 1 which is what I think we have been
 * following so far, if we were to use version 2 format_metric would need to be
 * converted to call this function multiple times with a single limit on each line.
 */

static void append_histogram_metric_value(struct cmt_map *map,
                                          cfl_sds_t *buf,
                                          struct cmt_metric *metric)
{
    size_t                        entry_buffer_length;
    size_t                        entry_buffer_index;
    char                          entry_buffer[256];
    struct cmt_histogram         *histogram;
    struct cmt_histogram_buckets *buckets;
    size_t                        index;

    histogram = (struct cmt_histogram *) map->parent;
    buckets = histogram->buckets;

    for (index = 0 ; index <= buckets->count ; index++) {
        if (index < buckets->count) {
            entry_buffer_index = snprintf(entry_buffer,
                                           sizeof(entry_buffer) - 1,
                                           "%g",
                                           buckets->upper_bounds[index]);
        }
        else {
            entry_buffer_index = snprintf(entry_buffer,
                                           sizeof(entry_buffer) - 1,
                                           "+Inf");
        }

        entry_buffer_length = entry_buffer_index;

        entry_buffer_length += snprintf(&entry_buffer[entry_buffer_index],
                                        sizeof(entry_buffer) - 1 -
                                        entry_buffer_index,
                                        "=%" PRIu64 ",",
                                        cmt_metric_hist_get_value(metric,
                                                                  index));

        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "sum=%.17g,",
                                   cmt_metric_hist_get_sum_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "count=%" PRIu64 " ",
                                   cmt_metric_hist_get_count_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "%" PRIu64 "\n",
                                   cmt_metric_get_timestamp(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
}

static void append_summary_metric_value(struct cmt_map *map,
                                        cfl_sds_t *buf,
                                        struct cmt_metric *metric)
{
    size_t              entry_buffer_length;
    char                entry_buffer[256];
    struct cmt_summary *summary;
    size_t              index;

    summary = (struct cmt_summary *) map->parent;

    for (index = 0 ; index < summary->quantiles_count ; index++) {
        entry_buffer_length = snprintf(entry_buffer,
                                       sizeof(entry_buffer) - 1,
                                       "%g=%.17g,",
                                       summary->quantiles[index],
                                       cmt_summary_quantile_get_value(metric,
                                                                      index));

        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "sum=%.17g,",
                                   cmt_summary_get_sum_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "count=%" PRIu64 " ",
                                   cmt_summary_get_count_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "%" PRIu64 "\n",
                                   cmt_metric_get_timestamp(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
}

static void append_metric_value(struct cmt_map *map,
                                cfl_sds_t *buf, struct cmt_metric *metric)
{
    int len;
    uint64_t ts;
    double val;
    char tmp[256];
    struct cmt_opts *opts;
    struct cmt_map fake_map;
    struct cmt_metric fake_metric;
    struct cmt_histogram fake_histogram;
    struct cmt_histogram_buckets fake_buckets;
    size_t bucket_count;
    size_t upper_bounds_count;
    uint64_t *bucket_values;
    double *upper_bounds;

    if (map->type == CMT_HISTOGRAM) {
        return append_histogram_metric_value(map, buf, metric);
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        if (cmt_exp_histogram_to_explicit(metric,
                                          &upper_bounds,
                                          &upper_bounds_count,
                                          &bucket_values,
                                          &bucket_count) == 0) {
            memset(&fake_map, 0, sizeof(struct cmt_map));
            memset(&fake_metric, 0, sizeof(struct cmt_metric));
            memset(&fake_histogram, 0, sizeof(struct cmt_histogram));
            memset(&fake_buckets, 0, sizeof(struct cmt_histogram_buckets));

            fake_buckets.count = upper_bounds_count;
            fake_buckets.upper_bounds = upper_bounds;
            fake_histogram.buckets = &fake_buckets;

            fake_map = *map;
            fake_map.type = CMT_HISTOGRAM;
            fake_map.parent = &fake_histogram;

            fake_metric = *metric;
            fake_metric.hist_buckets = bucket_values;
            fake_metric.hist_count = bucket_values[bucket_count - 1];
            fake_metric.hist_sum = cmt_atomic_load(&metric->exp_hist_sum);

            append_histogram_metric_value(&fake_map, buf, &fake_metric);

            free(bucket_values);
            free(upper_bounds);
        }

        return;
    }
    else if (map->type == CMT_SUMMARY) {
        return append_summary_metric_value(map, buf, metric);
    }

    opts = map->opts;

    /* Retrieve metric value */
    val = cmt_metric_get_value(metric);

    ts = cmt_metric_get_timestamp(metric);
    len = snprintf(tmp, sizeof(tmp) - 1, "=%.17g %" PRIu64 "\n", val, ts);

    cfl_sds_cat_safe(buf, opts->name, cfl_sds_len(opts->name));
    cfl_sds_cat_safe(buf, tmp, len);

}

static int line_protocol_escape(const char *str_in, int size_in,
                                char *str_out, int quote)
{
    int i;
    int size_out = 0;
    char ch;

    for (i = 0; i < size_in; ++i) {
        ch = str_in[i];
        if (quote ? (ch == '"' || ch == '\\') : (isspace(ch) || ch == ',' || ch == '=')) {
            str_out[size_out++] = '\\';
        }
        else if (ch == '\\') {
            str_out[size_out++] = '\\';
        }
        str_out[size_out++] = ch;
    }

    return size_out;
}

static int append_string(cfl_sds_t *buf, cfl_sds_t str)
{
    int len;
    int size;
    char *esc_buf;

    len = cfl_sds_len(str);
    esc_buf = malloc(len * 2);
    if (!esc_buf) {
        cmt_errno();
        return -1;
    }

    size = line_protocol_escape(str, len, esc_buf, 0);
    cfl_sds_cat_safe(buf, esc_buf, size);

    free(esc_buf);
    return 0;
}

static void format_metric(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    int i;
    int n;
    int static_count = 0;
    int static_labels = 0;
    int has_namespace = CMT_FALSE;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct cfl_list *head;
    struct cmt_opts *opts;
    struct cmt_label *slabel;

    if (map->type == CMT_SUMMARY && !cmt_atomic_load(&metric->sum_quantiles_set)) {
        return;
    }

    opts = map->opts;

    /* Measurement */
    if (cfl_sds_len(opts->ns) > 0) {
        cfl_sds_cat_safe(buf, opts->ns, cfl_sds_len(opts->ns));
        if (cfl_sds_len(opts->subsystem) > 0) {
            cfl_sds_cat_safe(buf, "_", 1);
            cfl_sds_cat_safe(buf, opts->subsystem, cfl_sds_len(opts->subsystem));
        }
        has_namespace = CMT_TRUE;
    }
    else {
        has_namespace = CMT_FALSE;
    }

    /* Static labels (tags) */
    static_labels = cmt_labels_count(cmt->static_labels);
    if (static_labels > 0) {
      if (has_namespace == CMT_TRUE) {
            cfl_sds_cat_safe(buf, ",", 1);
        }
        cfl_list_foreach(head, &cmt->static_labels->list) {
            static_count++;
            slabel = cfl_list_entry(head, struct cmt_label, _head);

            /* key */
            append_string(buf, slabel->key);

            /* = */
            cfl_sds_cat_safe(buf, "=", 1);

            /* val */
            append_string(buf, slabel->val);

            if (static_count < static_labels) {
                cfl_sds_cat_safe(buf, ",", 1);
            }
        }
    }

    /* Labels / Tags */
    n = cfl_list_size(&metric->labels);
    if (n > 0) {
        if (static_labels > 0 || has_namespace == CMT_TRUE) {
            cfl_sds_cat_safe(buf, ",", 1);
        }

        label_k = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        i = 1;
        cfl_list_foreach(head, &metric->labels) {
            label_v = cfl_list_entry(head, struct cmt_map_label, _head);

            /* key */
            append_string(buf, label_k->name);
            cfl_sds_cat_safe(buf, "=", 1);
            append_string(buf, label_v->name);

            if (i < n) {
                cfl_sds_cat_safe(buf, ",", 1);
            }
            i++;

            label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
        }
    }

    if (has_namespace == CMT_TRUE || static_labels > 0 || n > 0) {
        cfl_sds_cat_safe(buf, " ", 1);
    }
    append_metric_value(map, buf, metric);
}

static void format_metrics(struct cmt *cmt,
                           cfl_sds_t *buf, struct cmt_map *map)
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
cfl_sds_t cmt_encode_influx_create(struct cmt *cmt)
{
    cfl_sds_t buf;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;

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

    /* Exponential Histograms */
    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        format_metrics(cmt, &buf, exp_histogram->map);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        format_metrics(cmt, &buf, untyped->map);
    }

    return buf;
}

void cmt_encode_influx_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
