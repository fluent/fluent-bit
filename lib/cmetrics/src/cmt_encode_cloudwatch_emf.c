/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2024 The CMetrics Authors
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
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_time.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_encode_cloudwatch_emf.h>
#include <cmetrics/cmt_variant_utils.h>

static void pack_basic_header(mpack_writer_t *writer, struct cmt *cmt,
                              struct cmt_map *map, struct cmt_metric *metric)
{
    int labels = 0;
    int static_labels = 0;
    struct cfl_list      *head;
    struct cmt_map_label *label_k;
    struct cmt_label     *slabel;
    struct cmt_opts      *opts   = map->opts;

    mpack_write_cstr(writer, "_aws");

    mpack_start_map(writer, 2);

    /* Millisecond precision */
    mpack_write_cstr(writer, "Timestamp");
    mpack_write_u64(writer, cmt_metric_get_timestamp(metric) / 1000000L);

    mpack_write_cstr(writer, "CloudWatchMetrics");
    mpack_start_array(writer, 1);

    mpack_start_map(writer, 3);

    mpack_write_cstr(writer, "Namespace");
    if (opts->ns) {
        mpack_write_cstr(writer, opts->ns);
    }
    else {
        mpack_write_cstr(writer, "cmetrics-metrics");
    }

    mpack_write_cstr(writer, "Dimensions");

    static_labels = cmt_labels_count(cmt->static_labels);
    labels += static_labels;
    labels += map->label_count;
    mpack_start_array(writer, 1);
    mpack_start_array(writer, labels);
    cfl_list_foreach(head, &map->label_keys) {
        label_k = cfl_list_entry(head, struct cmt_map_label, _head);
        mpack_write_cstr(writer, label_k->name);
    }

    cfl_list_foreach(head, &cmt->static_labels->list) {
        slabel = cfl_list_entry(head, struct cmt_label, _head);
        mpack_write_cstr(writer, slabel->key);
    }
    mpack_finish_array(writer);  /* Dimensions (inner) */
    mpack_finish_array(writer);  /* Dimensions (outer) */
}

static void pack_basic_header_finish(mpack_writer_t *writer)
{
    mpack_finish_map(writer); /* CloudWatchMetrics (inner map) */
    mpack_finish_array(writer);  /* CloudWatchMetrics (outer array) */
    mpack_finish_map(writer); /* _aws */
}

static void pack_cmetrics_type(mpack_writer_t *writer, struct cmt *cmt,
                               struct cmt_map *map)
{
    mpack_write_cstr(writer, "prom_metric_type");
    if (map->type == CMT_COUNTER) {
        mpack_write_cstr(writer, "counter");
    }
    else if (map->type == CMT_GAUGE) {
        mpack_write_cstr(writer, "gauge");
    }
    else if (map->type == CMT_UNTYPED) {
        mpack_write_cstr(writer, "untyped");
    }
    else if (map->type == CMT_SUMMARY) {
        mpack_write_cstr(writer, "summary");
    }
    else if (map->type == CMT_HISTOGRAM) {
        mpack_write_cstr(writer, "histogram");
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        mpack_write_cstr(writer, "histogram");
    }
    else {
        mpack_write_cstr(writer, "");
    }
}

static void pack_histogram_metric(mpack_writer_t *writer, struct cmt *cmt,
                                  struct cmt_map *map, struct cmt_metric *metric)
{
    int i;
    int k;
    int index = 0;
    double val = 0.0;
    double tmp;
    uint64_t *hist_metrics = NULL;
    uint64_t *exp_bucket_counts = NULL;
    double *exp_upper_bounds = NULL;
    size_t exp_bucket_count = 0;
    size_t exp_upper_bounds_count = 0;
    size_t bucket_count = 0;
    struct cmt_opts      *opts   = map->opts;
    struct cmt_histogram *histogram = NULL;
    struct cmt_histogram_buckets *buckets = NULL;

    if (map->type == CMT_HISTOGRAM) {
        histogram = (struct cmt_histogram *) map->parent;
        buckets = histogram->buckets;
        bucket_count = buckets->count;
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        if (cmt_exp_histogram_to_explicit(metric,
                                          &exp_upper_bounds,
                                          &exp_upper_bounds_count,
                                          &exp_bucket_counts,
                                          &exp_bucket_count) != 0) {
            return;
        }

        bucket_count = exp_upper_bounds_count;
    }
    else {
        return;
    }

    hist_metrics = calloc(bucket_count + 1, sizeof(uint64_t));
    if (hist_metrics == NULL) {
        free(exp_bucket_counts);
        free(exp_upper_bounds);
        return;
    }

    for (i = 0; i <= bucket_count; i++) {
        if (map->type == CMT_HISTOGRAM) {
            hist_metrics[i] = cmt_metric_hist_get_value(metric, i);
        }
        else {
            hist_metrics[i] = exp_bucket_counts[i];
        }
    }

    for (i = 0; i <= bucket_count; i++) {
        index = i;

        for (k = i + 1; k <= bucket_count; k++) {
            if (hist_metrics[k] < hist_metrics[index]) {
                index = k;
            }
        }

        tmp = hist_metrics[i];
        hist_metrics[i] = hist_metrics[index];
        hist_metrics[index] = tmp;
    }
    mpack_write_cstr(writer, opts->fqname);
    mpack_start_map(writer, 4);
    mpack_write_cstr(writer, "Min");
    mpack_write_double(writer, hist_metrics[0]);
    mpack_write_cstr(writer, "Max");
    mpack_write_double(writer, hist_metrics[bucket_count - 1]);
    mpack_write_cstr(writer, "Sum");
    if (map->type == CMT_HISTOGRAM) {
        val = cmt_metric_hist_get_sum_value(metric);
    }
    else {
        val = cmt_math_uint64_to_d64(metric->exp_hist_sum);
    }
    mpack_write_double(writer, val);
    mpack_write_cstr(writer, "Count");
    if (map->type == CMT_HISTOGRAM) {
        val = cmt_metric_hist_get_count_value(metric);
    }
    else {
        val = metric->exp_hist_count;
    }
    mpack_write_double(writer, val);
    mpack_finish_map(writer);

    free(hist_metrics);
    free(exp_bucket_counts);
    free(exp_upper_bounds);
}

static void pack_summary_metric(mpack_writer_t *writer, struct cmt *cmt,
                                struct cmt_map *map, struct cmt_metric *metric)
{
    double val = 0.0;
    struct cmt_opts      *opts   = map->opts;
    struct cmt_summary   *summary = NULL;

    summary = (struct cmt_summary *) map->parent;

    mpack_write_cstr(writer, opts->fqname);
    mpack_start_map(writer, 4);
    mpack_write_cstr(writer, "Min");
    val = cmt_summary_quantile_get_value(metric, 0);
    mpack_write_double(writer, val);
    mpack_write_cstr(writer, "Max");
    val = cmt_summary_quantile_get_value(metric, summary->quantiles_count - 1);
    mpack_write_double(writer, val);
    mpack_write_cstr(writer, "Sum");
    val = cmt_summary_get_sum_value(metric);
    mpack_write_double(writer, val);
    mpack_write_cstr(writer, "Count");
    val = cmt_summary_get_count_value(metric);
    mpack_write_double(writer, val);
    mpack_finish_map(writer);
}

static int pack_metric(mpack_writer_t *writer, struct cmt *cmt,
                       struct cmt_map *map, struct cmt_metric *metric)
{
    int s = 0;
    double val = 0.0;
    int c_labels = 0;
    int static_labels = 0;
    struct cfl_list      *head;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct cmt_label     *slabel;
    struct cmt_opts      *opts   = map->opts;

    c_labels = cfl_list_size(&metric->labels);
    s = 3;

    if (c_labels > 0) {
        s += c_labels;
    }

    static_labels = cmt_labels_count(cmt->static_labels);
    if (static_labels > 0) {
        s += static_labels;
    }

    mpack_start_map(writer, s);

    pack_basic_header(writer, cmt, map, metric);

    /* Pack the actual metrics */
    mpack_write_cstr(writer, "Metrics");
    mpack_start_array(writer, 1);
    if (map->type == CMT_COUNTER) {
        mpack_start_map(writer, 3);
        mpack_write_cstr(writer, "Name");
        mpack_write_cstr(writer, opts->fqname);
        mpack_write_cstr(writer, "Unit");
        mpack_write_cstr(writer, CMT_EMF_UNIT_COUNTER);
        mpack_write_cstr(writer, "StorageResolution");
        mpack_write_int(writer, 60);
        mpack_finish_map(writer);
    }
    else {
        mpack_start_map(writer, 2);
        mpack_write_cstr(writer, "Name");
        mpack_write_cstr(writer, opts->fqname);
        mpack_write_cstr(writer, "StorageResolution");
        mpack_write_int(writer, 60);
        mpack_finish_map(writer);
    }
    mpack_finish_array(writer); /* Metrics */

    pack_basic_header_finish(writer);

    /* dimensions */
    if (c_labels > 0) {
        label_k = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        cfl_list_foreach(head, &metric->labels) {
            label_v = cfl_list_entry(head, struct cmt_map_label, _head);
            mpack_write_cstr(writer, label_k->name);
            mpack_write_cstr(writer, label_v->name);

            label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                          _head, &map->label_keys);
        }
    }

    if (static_labels > 0) {
        cfl_list_foreach(head, &cmt->static_labels->list) {
            slabel = cfl_list_entry(head, struct cmt_label, _head);
            mpack_write_cstr(writer, slabel->key);
            mpack_write_cstr(writer, slabel->val);
        }
    }

    /* metric type */
    pack_cmetrics_type(writer, cmt, map);

    /* metrics */
    if (map->type == CMT_SUMMARY) {
        pack_summary_metric(writer, cmt, map, metric);
    }
    else if (map->type == CMT_HISTOGRAM || map->type == CMT_EXP_HISTOGRAM) {
        pack_histogram_metric(writer, cmt, map, metric);
    }
    else {
        mpack_write_cstr(writer, opts->fqname);
        val = cmt_metric_get_value(metric);
        mpack_write_double(writer, val);
    }

    /* Finish creating up the EMF format for a metrics */
    mpack_finish_map(writer);

    return 0;
}

static void pack_metrics(mpack_writer_t *writer, struct cmt *cmt,
                         struct cmt_map *map)
{
    struct cfl_list *head;
    struct cmt_metric *metric = NULL;

    /* Simple metric, no labels */
    if (map->metric_static_set == 1) {
        pack_metric(writer, cmt, map, &map->metric);
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        pack_metric(writer, cmt, map, metric);
    }
}

static size_t count_metrics(struct cmt *cmt)
{
    size_t                metric_count;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    struct cmt_gauge     *gauge;
    struct cfl_list      *head;
    struct cmt_map       *map;

    metric_count  = 0;
    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        map = counter->map;
        if (map->metric_static_set == 1) {
            metric_count++;
        }
        metric_count += cfl_list_size(&map->metrics);
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        map = gauge->map;
        if (map->metric_static_set == 1) {
            metric_count++;
        }
        metric_count += cfl_list_size(&map->metrics);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        map = untyped->map;
        if (map->metric_static_set == 1) {
            metric_count++;
        }
        metric_count += cfl_list_size(&map->metrics);
    }

    /* Summary */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        map = summary->map;
        if (map->metric_static_set == 1) {
            metric_count++;
        }
        metric_count += cfl_list_size(&map->metrics);
    }

    /* Histogram */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        map = histogram->map;
        if (map->metric_static_set == 1) {
            metric_count++;
        }
        metric_count += cfl_list_size(&map->metrics);
    }

    /* Exponential Histogram */
    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        map = exp_histogram->map;
        if (map->metric_static_set == 1) {
            metric_count++;
        }
        metric_count += cfl_list_size(&map->metrics);
    }

    return metric_count;
}

static int pack_context_metrics(mpack_writer_t *writer, struct cmt *cmt, int wrap_array)
{
    size_t                metric_count;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    struct cmt_gauge     *gauge;
    struct cfl_list      *head;

    if (wrap_array == CMT_TRUE) {
        metric_count = count_metrics(cmt);
        mpack_start_array(writer, metric_count);
    }

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        pack_metrics(writer, cmt, counter->map);
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        pack_metrics(writer, cmt, gauge->map);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        pack_metrics(writer, cmt, untyped->map);
    }

    /* Summary */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        pack_metrics(writer, cmt, summary->map);
    }

    /* Histogram */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        pack_metrics(writer, cmt, histogram->map);
    }

    /* Exponential Histogram */
    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        pack_metrics(writer, cmt, exp_histogram->map);
    }

    if (wrap_array == CMT_TRUE) {
        mpack_finish_array(writer); /* outermost context scope */
    }

    return CMT_ENCODE_CLOUDWATCH_EMF_SUCCESS;
}

static int pack_emf_payload(mpack_writer_t *writer, struct cmt *cmt, int wrap_array)
{
    int result;

    result = pack_context_metrics(writer, cmt, wrap_array);

    if (result != CMT_ENCODE_CLOUDWATCH_EMF_SUCCESS) {
        return CMT_ENCODE_CLOUDWATCH_EMF_CREATION_FAILED;
    }

    return 0;
}

int cmt_encode_cloudwatch_emf_create(struct cmt *cmt,
                                     char **out_buf, size_t *out_size,
                                     int wrap_array)
{
    char *data;
    size_t size;
    mpack_writer_t writer;
    int result;

    if (cmt == NULL) {
        return CMT_ENCODE_CLOUDWATCH_EMF_INVALID_ARGUMENT_ERROR;
    }

    mpack_writer_init_growable(&writer, &data, &size);

    result = pack_emf_payload(&writer, cmt, wrap_array);

    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");

        return CMT_ENCODE_CLOUDWATCH_EMF_INVALID_DATA_ERROR;
    }

    if (result != 0) {
        return result;
    }

    *out_buf = data;
    *out_size = size;

    return 0;
}

void cmt_encode_cloudwatch_emf_destroy(char *out_buf)
{
    if (out_buf != NULL) {
        MPACK_FREE(out_buf);
    }
}
