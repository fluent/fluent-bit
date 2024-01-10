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
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>

static int copy_label_keys(struct cmt_map *map, char **out)
{
    int i;
    int s;
    char **labels = NULL;
    struct cfl_list *head;
    struct cmt_map_label *label;

    /* labels array */
    s = map->label_count;
    if (s == 0) {
        *out = NULL;
        return 0;
    }

    if (s > 0) {
        labels = malloc(sizeof(char *) * s);
        if (!labels) {
            cmt_errno();
            return -1;
        }
    }

    /* label keys: by using the labels array, just point out the names */
    i = 0;
    cfl_list_foreach(head, &map->label_keys) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        labels[i] = label->name;
        i++;
    }

    *out = (char *) labels;
    return i;
}

static int copy_label_values(struct cmt_metric *metric, char **out)
{
    int i;
    int s;
    char **labels = NULL;
    struct cfl_list *head;
    struct cmt_map_label *label;

    /* labels array */
    s = cfl_list_size(&metric->labels);
    if (s == 0) {
        *out = NULL;
        return 0;
    }

    if (s > 0) {
        labels = malloc(sizeof(char *) * s);
        if (!labels) {
            cmt_errno();
            return -1;
        }
    }

    /* label keys: by using the labels array, just point out the names */
    i = 0;
    cfl_list_foreach(head, &metric->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        labels[i] = label->name;
        i++;
    }

    *out = (char *) labels;
    return i;
}

static int copy_map(struct cmt_opts *opts, struct cmt_map *dst, struct cmt_map *src)
{
    int i;
    int c;
    int ret;
    uint64_t ts;
    double val;
    char **labels = NULL;
    struct cfl_list *head;
    struct cmt_metric *metric_dst;
    struct cmt_metric *metric_src;

    /* Handle static metric (no labels case) */
    if (src->metric_static_set) {
        dst->metric_static_set = CMT_TRUE;

        /* destination and source metric */
        metric_dst = &dst->metric;
        metric_src = &src->metric;

        ts  = cmt_metric_get_timestamp(metric_src);
        val = cmt_metric_get_value(metric_src);

        cmt_metric_set(metric_dst, ts, val);
    }

    /* Process map dynamic metrics */
    cfl_list_foreach(head, &src->metrics) {
        metric_src = cfl_list_entry(head, struct cmt_metric, _head);

        ret = copy_label_values(metric_src, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        c = cfl_list_size(&metric_src->labels);
        metric_dst = cmt_map_metric_get(opts, dst, c, labels, CMT_TRUE);
        free(labels);

        if (!metric_dst) {
            return -1;
        }

        if (src->type == CMT_HISTOGRAM) {
            if (!metric_dst->hist_buckets) {
                metric_dst->hist_buckets = calloc(1, sizeof(uint64_t) * (metric_src->hist_count + 1));
                if (!metric_dst->hist_buckets) {
                    return -1;
                }
            }
            for (i = 0; i < metric_src->hist_count; i++) {
                metric_dst->hist_buckets[i] = metric_src->hist_buckets[i];
            }
            metric_dst->hist_count = metric_src->hist_count;
            metric_dst->hist_sum = metric_src->hist_sum;
        }
        else if (src->type == CMT_SUMMARY) {
            metric_dst->sum_quantiles_count = metric_src->sum_quantiles_count;
            metric_dst->sum_quantiles_set = metric_src->sum_quantiles_set;
            if (!metric_dst->sum_quantiles) {
                metric_dst->sum_quantiles = calloc(1, sizeof(uint64_t) * (metric_src->sum_quantiles_count));
                if (!metric_dst->sum_quantiles) {
                    return -1;
                }
            }
            for (i = 0; i < metric_src->sum_quantiles_count; i++) {
                metric_dst->sum_quantiles[i] = metric_src->sum_quantiles[i];
            }
            metric_dst->sum_count = metric_src->sum_count;
            metric_dst->sum_sum = metric_src->sum_sum;
        }

        ts  = cmt_metric_get_timestamp(metric_src);
        val = cmt_metric_get_value(metric_src);

        cmt_metric_set(metric_dst, ts, val);
    }

    return 0;

}

static int copy_counter(struct cmt *cmt, struct cmt_counter *counter)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_counter *c;

    map = counter->map;
    opts = map->opts;

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    /* create counter */
    c = cmt_counter_create(cmt,
                           opts->ns, opts->subsystem,
                           opts->name, opts->description,
                           map->label_count, labels);

    free(labels);
    if (!c) {
        return -1;
    }

    ret = copy_map(&c->opts, c->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int copy_gauge(struct cmt *cmt, struct cmt_gauge *gauge)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_gauge *g;

    map = gauge->map;
    opts = map->opts;

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    /* create counter */
    g = cmt_gauge_create(cmt,
                         opts->ns, opts->subsystem,
                         opts->name, opts->description,
                         map->label_count, labels);
    free(labels);
    if (!g) {
        return -1;
    }

    ret = copy_map(&g->opts, g->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int copy_untyped(struct cmt *cmt, struct cmt_untyped *untyped)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_untyped *u;

    map = untyped->map;
    opts = map->opts;

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    /* create counter */
    u = cmt_untyped_create(cmt,
                           opts->ns, opts->subsystem,
                           opts->name, opts->description,
                           map->label_count, labels);
    free(labels);
    if (!u) {
        return -1;
    }

    ret = copy_map(&u->opts, u->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int copy_histogram(struct cmt *cmt, struct cmt_histogram *histogram)
{
    int i;
    double val;
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_histogram *hist;
    uint64_t timestamp;
    struct cmt_histogram_buckets *buckets;
    int64_t buckets_count;

    map = histogram->map;
    opts = map->opts;
    timestamp = cmt_metric_get_timestamp(&map->metric);

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    buckets_count = histogram->buckets->count;
    buckets = cmt_histogram_buckets_create_size(histogram->buckets->upper_bounds,
                                                buckets_count);

    /* create histogram */
    hist = cmt_histogram_create(cmt,
                                opts->ns, opts->subsystem,
                                opts->name, opts->description,
                                buckets,
                                map->label_count, labels);
    if (!hist) {
        return -1;
    }

    for (i = 0; i < buckets_count; i++) {
        val = histogram->buckets->upper_bounds[i];
        cmt_histogram_observe(hist, timestamp, val, map->label_count, labels);
    }
    free(labels);

    ret = copy_map(&hist->opts, hist->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int copy_summary(struct cmt *cmt, struct cmt_summary *summary)
{
    int i;
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_summary *sum;
    double *quantiles;
    uint64_t timestamp;
    double summary_sum;

    map = summary->map;
    opts = map->opts;
    timestamp = cmt_metric_get_timestamp(&map->metric);

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    quantiles = calloc(1, sizeof(double) * summary->quantiles_count);
    for (i = 0; i < summary->quantiles_count; i++) {
        quantiles[i] = summary->quantiles[i];
    }

    /* create summary */
    sum = cmt_summary_create(cmt,
                             opts->ns, opts->subsystem,
                             opts->name, opts->description,
                             summary->quantiles_count,
                             quantiles,
                             map->label_count, labels);
    if (!sum) {
        return -1;
    }

    summary_sum = cmt_summary_get_sum_value(&summary->map->metric);

    cmt_summary_set_default(sum, timestamp, quantiles, summary_sum, summary->quantiles_count, map->label_count, labels);
    free(labels);
    free(quantiles);

    ret = copy_map(&sum->opts, sum->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int append_context(struct cmt *dst, struct cmt *src)
{
    int ret;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_summary *summary;

     /* Counters */
    cfl_list_foreach(head, &src->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        ret = copy_counter(dst, counter);
        if (ret == -1) {
            return -1;
        }
    }

    /* Gauges */
    cfl_list_foreach(head, &src->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        ret = copy_gauge(dst, gauge);
        if (ret == -1) {
            return -1;
        }
    }

    /* Untyped */
    cfl_list_foreach(head, &src->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        ret = copy_untyped(dst, untyped);
        if (ret == -1) {
            return -1;
        }
    }

    /* Histogram */
    cfl_list_foreach(head, &src->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        ret = copy_histogram(dst, histogram);
        if (ret == -1) {
            return -1;
        }
    }

    /* Summary */
    cfl_list_foreach(head, &src->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        ret = copy_summary(dst, summary);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int cmt_cat(struct cmt *dst, struct cmt *src)
{
    if (!dst) {
        return -1;
    }

    if (!src) {
        return -1;
    }

    return append_context(dst, src);
}
