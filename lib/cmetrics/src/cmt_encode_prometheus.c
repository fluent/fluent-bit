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

#include <stdbool.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>

#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_compat.h>

#define PROM_FMT_VAL_FROM_VAL          0
#define PROM_FMT_VAL_FROM_BUCKET_ID    1
#define PROM_FMT_VAL_FROM_QUANTILE     2
#define PROM_FMT_VAL_FROM_SUM          3
#define PROM_FMT_VAL_FROM_COUNT        4

struct prom_fmt {
    int metric_name;   /* metric name already set ? */
    int brace_open;    /* first brace open ? */
    int labels_count;  /* number of labels aready added */
    int value_from;

    /*
     * For value_from 'PROM_FMT_VAL_FROM_BUCKET_ID', the 'id' belongs to a bucket
     * id position, if is 'PROM_FMT_VAL_FROM_QUANTILE' the value represents a
     * sum_quantiles position.
     */
    int id;
};

static void prom_fmt_init(struct prom_fmt *fmt)
{
    fmt->metric_name = CMT_FALSE;
    fmt->brace_open = CMT_FALSE;
    fmt->labels_count = 0;
    fmt->value_from = PROM_FMT_VAL_FROM_VAL;
    fmt->id = -1;
}

/*
 * Prometheus Exposition Format
 * ----------------------------
 * https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md
 */

static void metric_escape(cfl_sds_t *buf, cfl_sds_t description, bool escape_quote)
{
    int i;
    size_t len;

    len = cfl_sds_len(description);

    for (i = 0; i < len; i++) {
        switch (description[i]) {
            case '\\':
                cfl_sds_cat_safe(buf, "\\\\", 2);
                break;
            case '\n':
                cfl_sds_cat_safe(buf, "\\n", 2);
                break;
            case '"':
                if (escape_quote) {
                    cfl_sds_cat_safe(buf, "\\\"", 2);
                    break;
                }
                /* FALLTHROUGH */
            default:
                cfl_sds_cat_safe(buf, description + i, 1);
                break;
        }
    }
}

static void metric_banner(cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    struct cmt_opts *opts;

    opts = map->opts;

    /* HELP */
    cfl_sds_cat_safe(buf, "# HELP ", 7);
    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));

    if (cfl_sds_len(opts->description) > 1 || opts->description[0] != ' ') {
        /* only append description if it is not empty. the parser uses a single whitespace
         * string to signal that no HELP was provided */
        cfl_sds_cat_safe(buf, " ", 1);
        metric_escape(buf, opts->description, false);
    }
    cfl_sds_cat_safe(buf, "\n", 1);

    /* TYPE */
    cfl_sds_cat_safe(buf, "# TYPE ", 7);
    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));

    if (map->type == CMT_COUNTER) {
        cfl_sds_cat_safe(buf, " counter\n", 9);
    }
    else if (map->type == CMT_GAUGE) {
        cfl_sds_cat_safe(buf, " gauge\n", 7);
    }
    else if (map->type == CMT_SUMMARY) {
        cfl_sds_cat_safe(buf, " summary\n", 9);
    }
    else if (map->type == CMT_HISTOGRAM) {
        cfl_sds_cat_safe(buf, " histogram\n", 11);
    }
    else if (map->type == CMT_UNTYPED) {
        cfl_sds_cat_safe(buf, " untyped\n", 9);
    }
}

static void append_metric_value(cfl_sds_t *buf,
                                struct cmt_map *map,
                                struct cmt_metric *metric,
                                struct prom_fmt *fmt, int add_timestamp)
{
    int len;
    double val = 0.0;
    uint64_t ts;
    char tmp[128];

    /*
     * Retrieve metric value
     * ---------------------
     * the formatter 'fmt->value_from' specifies from 'where' the value must
     * be retrieved from, note the 'metric' structure contains one generic
     * value field plus others associated to histograms.
     */
    if (fmt->value_from == PROM_FMT_VAL_FROM_VAL) {
        /* get 'normal' metric value */
        val = cmt_metric_get_value(metric);
    }
    else if (fmt->value_from == PROM_FMT_VAL_FROM_BUCKET_ID) {
        /* retrieve the value from a bucket */
        val = cmt_metric_hist_get_value(metric, fmt->id);
    }
    else if (fmt->value_from == PROM_FMT_VAL_FROM_QUANTILE) {
        /* retrieve the value from a bucket */
        val = cmt_summary_quantile_get_value(metric, fmt->id);
    }
    else {
        if (map->type == CMT_HISTOGRAM) {
            if (fmt->value_from == PROM_FMT_VAL_FROM_SUM) {
                val = cmt_metric_hist_get_sum_value(metric);
            }
            else if (fmt->value_from == PROM_FMT_VAL_FROM_COUNT) {
                val = cmt_metric_hist_get_count_value(metric);
            }
        }
        else if (map->type == CMT_SUMMARY) {
            if (fmt->value_from == PROM_FMT_VAL_FROM_SUM) {
                val = cmt_summary_get_sum_value(metric);
            }
            else if (fmt->value_from == PROM_FMT_VAL_FROM_COUNT) {
                val = cmt_summary_get_count_value(metric);
            }
        }
    }

    if (add_timestamp) {
        ts = cmt_metric_get_timestamp(metric);

        /* convert from nanoseconds to milliseconds */
        ts /= 1000000;

        len = snprintf(tmp, sizeof(tmp) - 1, " %.17g %" PRIu64 "\n", val, ts);
    }
    else {
        len = snprintf(tmp, sizeof(tmp) - 1, " %.17g\n", val);
    }
    cfl_sds_cat_safe(buf, tmp, len);
}

static int add_label(cfl_sds_t *buf, cfl_sds_t key, cfl_sds_t val)
{
    cfl_sds_cat_safe(buf, key, cfl_sds_len(key));
    cfl_sds_cat_safe(buf, "=\"", 2);
    metric_escape(buf, val, true);
    cfl_sds_cat_safe(buf, "\"", 1);

    return 1;
}

static int add_static_labels(struct cmt *cmt, cfl_sds_t *buf)
{
    int count = 0;
    int total = 0;
    struct cfl_list *head;
    struct cmt_label *label;

    total = cfl_list_size(&cmt->static_labels->list);
    cfl_list_foreach(head, &cmt->static_labels->list) {
        label = cfl_list_entry(head, struct cmt_label, _head);

        count += add_label(buf, label->key, label->val);
        if (count < total) {
            cfl_sds_cat_safe(buf, ",", 1);
        }
    }

    return count;
}

static void format_metric(struct cmt *cmt,
                          cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric, int add_timestamp,
                          struct prom_fmt *fmt)
{
    int i;
    int static_labels = 0;
    int defined_labels = 0;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct cfl_list *head;
    struct cmt_opts *opts;

    opts = map->opts;

    /* Metric info */
    if (!fmt->metric_name) {
        cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));
    }

    /* Static labels */
    static_labels = cmt_labels_count(cmt->static_labels);
    cfl_list_foreach(head, &metric->labels) {
        label_v = cfl_list_entry(head, struct cmt_map_label, _head);
        if (strlen(label_v->name)) {
            defined_labels++;
        }
    }

    if (!fmt->brace_open && (static_labels + defined_labels > 0)) {
        cfl_sds_cat_safe(buf, "{", 1);
    }

    if (static_labels > 0) {
        /* if some labels were added before, add the separator */
        if (fmt->labels_count > 0) {
            cfl_sds_cat_safe(buf, ",", 1);
        }
        fmt->labels_count += add_static_labels(cmt, buf);
    }

    /* Append api defined labels */
    if (defined_labels > 0) {
        if (fmt->labels_count > 0) {
            cfl_sds_cat_safe(buf, ",", 1);
        }

        i = 1;
        label_k = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);
        cfl_list_foreach(head, &metric->labels) {
            label_v = cfl_list_entry(head, struct cmt_map_label, _head);

            if (strlen(label_v->name)) {
                fmt->labels_count += add_label(buf, label_k->name, label_v->name);
                if (i < defined_labels) {
                    cfl_sds_cat_safe(buf, ",", 1);
                }

                i++;
            }

            label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
        }
    }

    if (fmt->labels_count > 0) {
        cfl_sds_cat_safe(buf, "}", 1);
    }

    append_metric_value(buf, map, metric, fmt, add_timestamp);
}

static cfl_sds_t bucket_value_to_string(double val)
{
    int len;
    cfl_sds_t str;

    str = cfl_sds_create_size(64);
    if (!str) {
        return NULL;
    }

    len = snprintf(str, 64, "%g", val);
    cfl_sds_len_set(str, len);

    if (!strchr(str, '.')) {
        cfl_sds_cat_safe(&str, ".0", 2);
    }

    return str;
}

static void format_histogram_bucket(struct cmt *cmt,
                                    cfl_sds_t *buf, struct cmt_map *map,
                                    struct cmt_metric *metric, int add_timestamp)
{
    int i;
    cfl_sds_t val;
    struct cmt_histogram *histogram;
    struct cmt_histogram_buckets *bucket;
    struct cmt_opts *opts;
    struct prom_fmt fmt = {0};

    histogram = (struct cmt_histogram *) map->parent;
    bucket = histogram->buckets;
    opts = map->opts;

    for (i = 0; i <= bucket->count; i++) {
        /* metric name */
        cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));
        cfl_sds_cat_safe(buf, "_bucket", 7);

        /* upper bound */
        cfl_sds_cat_safe(buf, "{le=\"", 5);

        if (i < bucket->count) {
            val = bucket_value_to_string(bucket->upper_bounds[i]);
            cfl_sds_cat_safe(buf, val, cfl_sds_len(val));
            cfl_sds_destroy(val);
        }
        else {
            cfl_sds_cat_safe(buf, "+Inf", 4);
        }
        cfl_sds_cat_safe(buf, "\"", 1);

        /* configure formatter */
        fmt.metric_name  = CMT_TRUE;
        fmt.brace_open   = CMT_TRUE;
        fmt.labels_count = 1;
        fmt.value_from   = PROM_FMT_VAL_FROM_BUCKET_ID;
        fmt.id           = i;

        /* append metric labels, value and timestamp */
        format_metric(cmt, buf, map, metric, add_timestamp, &fmt);
    }

    /* sum */
    prom_fmt_init(&fmt);
    fmt.metric_name = CMT_TRUE;
    fmt.value_from = PROM_FMT_VAL_FROM_SUM;

    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));
    cfl_sds_cat_safe(buf, "_sum", 4);
    format_metric(cmt, buf, map, metric, add_timestamp, &fmt);

    /* count */
    fmt.labels_count = 0;
    fmt.value_from = PROM_FMT_VAL_FROM_COUNT;

    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));
    cfl_sds_cat_safe(buf, "_count", 6);
    format_metric(cmt, buf, map, metric, add_timestamp, &fmt);
}

static void format_summary_quantiles(struct cmt *cmt,
                                     cfl_sds_t *buf, struct cmt_map *map,
                                     struct cmt_metric *metric, int add_timestamp)
{
    int i;
    cfl_sds_t val;
    struct cmt_summary *summary;
    struct cmt_opts *opts;
    struct prom_fmt fmt = {0};

    summary = (struct cmt_summary *) map->parent;
    opts = map->opts;

    if (metric->sum_quantiles_set) {
        for (i = 0; i < summary->quantiles_count; i++) {
            /* metric name */
            cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));

            /* quantiles */
            cfl_sds_cat_safe(buf, "{quantile=\"", 11);
            val = bucket_value_to_string(summary->quantiles[i]);
            cfl_sds_cat_safe(buf, val, cfl_sds_len(val));
            cfl_sds_destroy(val);
            cfl_sds_cat_safe(buf, "\"", 1);

            /* configure formatter */
            fmt.metric_name  = CMT_TRUE;
            fmt.brace_open   = CMT_TRUE;
            fmt.labels_count = 1;
            fmt.value_from   = PROM_FMT_VAL_FROM_QUANTILE;
            fmt.id           = i;

            /* append metric labels, value and timestamp */
            format_metric(cmt, buf, map, metric, add_timestamp, &fmt);
        }
    }

    /* sum */
    prom_fmt_init(&fmt);
    fmt.metric_name = CMT_TRUE;
    fmt.value_from = PROM_FMT_VAL_FROM_SUM;

    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));
    cfl_sds_cat_safe(buf, "_sum", 4);
    format_metric(cmt, buf, map, metric, add_timestamp, &fmt);

    /* count */
    fmt.labels_count = 0;
    fmt.value_from = PROM_FMT_VAL_FROM_COUNT;

    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));
    cfl_sds_cat_safe(buf, "_count", 6);
    format_metric(cmt, buf, map, metric, add_timestamp, &fmt);
}

static void format_metrics(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map,
                           int add_timestamp)
{
    int banner_set = CMT_FALSE;
    struct cfl_list *head;
    struct cmt_metric *metric;
    struct prom_fmt fmt = {0};

    /* Simple metric, no labels */
    if (map->metric_static_set) {
        metric_banner(buf, map, &map->metric);
        banner_set = CMT_TRUE;

        if (map->type == CMT_HISTOGRAM) {
            /* Histogram needs to format the buckets, one line per bucket */
            format_histogram_bucket(cmt, buf, map, &map->metric, add_timestamp);
        }
        else if (map->type == CMT_SUMMARY) {
            /* Histogram needs to format the buckets, one line per bucket */
            format_summary_quantiles(cmt, buf, map, &map->metric, add_timestamp);
        }
        else {
            prom_fmt_init(&fmt);
            format_metric(cmt, buf, map, &map->metric, add_timestamp, &fmt);
        }
    }

    if (cfl_list_size(&map->metrics) > 0) {
        metric = cfl_list_entry_first(&map->metrics, struct cmt_metric, _head);
        if (!banner_set) {
            metric_banner(buf, map, metric);
        }
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);

        /* Format the metric based on its type */
        if (map->type == CMT_HISTOGRAM) {
            /* Histogram needs to format the buckets, one line per bucket */
            format_histogram_bucket(cmt, buf, map, metric, add_timestamp);
        }
        else if (map->type == CMT_SUMMARY) {
            format_summary_quantiles(cmt, buf, map, metric, add_timestamp);
        }
        else {
            prom_fmt_init(&fmt);
            format_metric(cmt, buf, map, metric, add_timestamp, &fmt);
        }
    }
}

/* Format all the registered metrics in Prometheus Text format */
cfl_sds_t cmt_encode_prometheus_create(struct cmt *cmt, int add_timestamp)
{
    cfl_sds_t buf;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_untyped *untyped;

    /* Allocate a 1KB of buffer */
    buf = cfl_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        format_metrics(cmt, &buf, counter->map, add_timestamp);
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        format_metrics(cmt, &buf, gauge->map, add_timestamp);
    }

    /* Summaries */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        format_metrics(cmt, &buf, summary->map, add_timestamp);
    }

    /* Histograms */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        format_metrics(cmt, &buf, histogram->map, add_timestamp);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        format_metrics(cmt, &buf, untyped->map, add_timestamp);
    }

    return buf;
}

void cmt_encode_prometheus_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
