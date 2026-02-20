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
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_atomic.h>

int cmt_cat_copy_label_keys(struct cmt_map *map, char **out)
{
    int i;
    int s;
    char **labels = NULL;
    struct cfl_list *head;
    struct cmt_map_label *label;

    /* labels array */
    s = map->label_count;
    if (s <= 0) {
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

static inline int cat_histogram_values(struct cmt_metric *metric_dst, struct cmt_histogram *histogram_src,
                                       struct cmt_metric *metric_src, struct cmt_histogram *histogram_dst)
{
    int i;
    int result;
    uint64_t old_value;
    uint64_t new_value;
    size_t bucket_count_src;
    size_t bucket_count_dst;

    /* Validate source histogram buckets exist */
    if (!metric_src->hist_buckets) {
        /* Source has no bucket data, nothing to concatenate */
        return 0;
    }

    bucket_count_src = histogram_src->buckets->count;
    bucket_count_dst = histogram_dst->buckets->count;

    /* Validate that source and destination have matching bucket structures */
    if (bucket_count_src != bucket_count_dst) {
        /* Histogram bucket structures don't match - cannot concatenate */
        return -1;
    }

    /* Allocate destination buckets if needed */
    if (!metric_dst->hist_buckets) {
        metric_dst->hist_buckets = calloc(1, sizeof(uint64_t) * (bucket_count_dst + 1));
        if (!metric_dst->hist_buckets) {
            return -1;
        }
    }

    /* Concatenate bucket values including +Inf bucket at index bucket_count_dst */
    for (i = 0; i <= bucket_count_dst; i++) {
        do {
            old_value = cmt_atomic_load(&metric_dst->hist_buckets[i]);
            new_value = old_value + cmt_atomic_load(&metric_src->hist_buckets[i]);
            result = cmt_atomic_compare_exchange(&metric_dst->hist_buckets[i],
                                                 old_value, new_value);
        }
        while (result == 0);
    }

    /* histogram count */
    do {
        old_value = cmt_atomic_load(&metric_dst->hist_count);
        new_value = cmt_math_sum_native_uint64_as_d64(
                        old_value,
                        cmt_atomic_load(&metric_src->hist_count));
        result = cmt_atomic_compare_exchange(&metric_dst->hist_count,
                                             old_value, new_value);
    }
    while (result == 0);

    /* histoggram sum */
    do {
        old_value = cmt_atomic_load(&metric_dst->hist_sum);
        new_value = cmt_math_sum_native_uint64_as_d64(
                        old_value,
                        cmt_atomic_load(&metric_src->hist_sum));
        result = cmt_atomic_compare_exchange(&metric_dst->hist_sum,
                                             old_value, new_value);
    }
    while (result == 0);

    return 0;
}

/*
 * For summaries we don't support manual updates through the API, on concatenation we just
 * keep the last values reported.
 */
static inline int cat_summary_values(struct cmt_metric *metric_dst, struct cmt_summary *summary,
                                     struct cmt_metric *metric_src)
{
    int i;

    if (!metric_dst->sum_quantiles) {
        metric_dst->sum_quantiles = calloc(1, sizeof(uint64_t) * (summary->quantiles_count));
        if (!metric_dst->sum_quantiles) {
            return -1;
        }
    }

    for (i = 0; i < summary->quantiles_count; i++) {
        cmt_atomic_store(&metric_dst->sum_quantiles[i],
                         cmt_atomic_load(&metric_src->sum_quantiles[i]));
    }

    metric_dst->sum_quantiles_count = metric_src->sum_quantiles_count;
    cmt_atomic_store(&metric_dst->sum_quantiles_set, cmt_atomic_load(&metric_src->sum_quantiles_set));

    cmt_atomic_store(&metric_dst->sum_count, cmt_atomic_load(&metric_src->sum_count));
    cmt_atomic_store(&metric_dst->sum_sum, cmt_atomic_load(&metric_src->sum_sum));

    return 0;
}

static inline int cat_exp_histogram_values(struct cmt_metric *metric_dst,
                                           struct cmt_metric *metric_src)
{
    int result;
    struct cmt_metric *first_lock_target;
    struct cmt_metric *second_lock_target;
    int64_t dst_start;
    int64_t dst_end;
    int64_t src_start;
    int64_t src_end;
    int64_t merged_start;
    int64_t merged_end;
    size_t index;
    size_t merged_count;
    uint64_t old_value;
    uint64_t new_value;
    uint64_t *merged_buckets;
    uint64_t *tmp_buckets;

    result = -1;
    first_lock_target = metric_dst;
    second_lock_target = metric_src;

    if (first_lock_target > second_lock_target) {
        first_lock_target = metric_src;
        second_lock_target = metric_dst;
    }

    cmt_metric_exp_hist_lock(first_lock_target);

    if (second_lock_target != first_lock_target) {
        cmt_metric_exp_hist_lock(second_lock_target);
    }

    if (metric_dst->exp_hist_positive_count > 0 &&
        metric_dst->exp_hist_positive_buckets == NULL) {
        goto cleanup;
    }

    if (metric_dst->exp_hist_negative_count > 0 &&
        metric_dst->exp_hist_negative_buckets == NULL) {
        goto cleanup;
    }

    if (metric_src->exp_hist_positive_count > 0 &&
        metric_src->exp_hist_positive_buckets == NULL) {
        goto cleanup;
    }

    if (metric_src->exp_hist_negative_count > 0 &&
        metric_src->exp_hist_negative_buckets == NULL) {
        goto cleanup;
    }

    if (metric_dst->exp_hist_positive_buckets == NULL &&
        metric_dst->exp_hist_negative_buckets == NULL &&
        metric_dst->exp_hist_positive_count == 0 &&
        metric_dst->exp_hist_negative_count == 0 &&
        cmt_atomic_load(&metric_dst->exp_hist_count) == 0 &&
        metric_dst->exp_hist_zero_count == 0 &&
        cmt_atomic_load(&metric_dst->exp_hist_sum) == 0 &&
        metric_dst->exp_hist_scale == 0 &&
        metric_dst->exp_hist_positive_offset == 0 &&
        metric_dst->exp_hist_negative_offset == 0 &&
        metric_dst->exp_hist_zero_threshold == 0.0) {
        if (metric_src->exp_hist_positive_count > 0) {
            metric_dst->exp_hist_positive_buckets = calloc(metric_src->exp_hist_positive_count,
                                                           sizeof(uint64_t));
            if (metric_dst->exp_hist_positive_buckets == NULL) {
                goto cleanup;
            }

            memcpy(metric_dst->exp_hist_positive_buckets,
                   metric_src->exp_hist_positive_buckets,
                   sizeof(uint64_t) * metric_src->exp_hist_positive_count);
        }

        if (metric_src->exp_hist_negative_count > 0) {
            metric_dst->exp_hist_negative_buckets = calloc(metric_src->exp_hist_negative_count,
                                                           sizeof(uint64_t));
            if (metric_dst->exp_hist_negative_buckets == NULL) {
                free(metric_dst->exp_hist_positive_buckets);
                metric_dst->exp_hist_positive_buckets = NULL;

                goto cleanup;
            }

            memcpy(metric_dst->exp_hist_negative_buckets,
                   metric_src->exp_hist_negative_buckets,
                   sizeof(uint64_t) * metric_src->exp_hist_negative_count);
        }

        metric_dst->exp_hist_scale = metric_src->exp_hist_scale;
        metric_dst->exp_hist_zero_count = metric_src->exp_hist_zero_count;
        metric_dst->exp_hist_zero_threshold = metric_src->exp_hist_zero_threshold;
        metric_dst->exp_hist_positive_offset = metric_src->exp_hist_positive_offset;
        metric_dst->exp_hist_positive_count = metric_src->exp_hist_positive_count;
        metric_dst->exp_hist_negative_offset = metric_src->exp_hist_negative_offset;
        metric_dst->exp_hist_negative_count = metric_src->exp_hist_negative_count;
        cmt_atomic_store(&metric_dst->exp_hist_count,
                         cmt_atomic_load(&metric_src->exp_hist_count));
        cmt_atomic_store(&metric_dst->exp_hist_sum_set,
                         cmt_atomic_load(&metric_src->exp_hist_sum_set));
        cmt_atomic_store(&metric_dst->exp_hist_sum,
                         cmt_atomic_load(&metric_src->exp_hist_sum));

        result = 0;
        goto cleanup;
    }

    if (metric_dst->exp_hist_scale != metric_src->exp_hist_scale ||
        metric_dst->exp_hist_zero_threshold != metric_src->exp_hist_zero_threshold) {
        goto cleanup;
    }

    if (metric_src->exp_hist_positive_count > 0) {
        if (metric_dst->exp_hist_positive_count == 0) {
            metric_dst->exp_hist_positive_buckets = calloc(metric_src->exp_hist_positive_count,
                                                           sizeof(uint64_t));
            if (metric_dst->exp_hist_positive_buckets == NULL) {
                goto cleanup;
            }

            memcpy(metric_dst->exp_hist_positive_buckets,
                   metric_src->exp_hist_positive_buckets,
                   sizeof(uint64_t) * metric_src->exp_hist_positive_count);
            metric_dst->exp_hist_positive_offset = metric_src->exp_hist_positive_offset;
            metric_dst->exp_hist_positive_count = metric_src->exp_hist_positive_count;
        }
        else {
            dst_start = metric_dst->exp_hist_positive_offset;
            dst_end = dst_start + metric_dst->exp_hist_positive_count;
            src_start = metric_src->exp_hist_positive_offset;
            src_end = src_start + metric_src->exp_hist_positive_count;

            merged_start = dst_start < src_start ? dst_start : src_start;
            merged_end = dst_end > src_end ? dst_end : src_end;
            merged_count = (size_t) (merged_end - merged_start);

            merged_buckets = calloc(merged_count, sizeof(uint64_t));
            if (merged_buckets == NULL) {
                goto cleanup;
            }

            for (index = 0; index < metric_dst->exp_hist_positive_count; index++) {
                merged_buckets[(size_t) (dst_start + index - merged_start)] +=
                    metric_dst->exp_hist_positive_buckets[index];
            }

            for (index = 0; index < metric_src->exp_hist_positive_count; index++) {
                merged_buckets[(size_t) (src_start + index - merged_start)] +=
                    metric_src->exp_hist_positive_buckets[index];
            }

            tmp_buckets = metric_dst->exp_hist_positive_buckets;
            metric_dst->exp_hist_positive_buckets = merged_buckets;
            metric_dst->exp_hist_positive_offset = (int32_t) merged_start;
            metric_dst->exp_hist_positive_count = merged_count;
            free(tmp_buckets);
        }
    }

    if (metric_src->exp_hist_negative_count > 0) {
        if (metric_dst->exp_hist_negative_count == 0) {
            metric_dst->exp_hist_negative_buckets = calloc(metric_src->exp_hist_negative_count,
                                                           sizeof(uint64_t));
            if (metric_dst->exp_hist_negative_buckets == NULL) {
                goto cleanup;
            }

            memcpy(metric_dst->exp_hist_negative_buckets,
                   metric_src->exp_hist_negative_buckets,
                   sizeof(uint64_t) * metric_src->exp_hist_negative_count);
            metric_dst->exp_hist_negative_offset = metric_src->exp_hist_negative_offset;
            metric_dst->exp_hist_negative_count = metric_src->exp_hist_negative_count;
        }
        else {
            dst_start = metric_dst->exp_hist_negative_offset;
            dst_end = dst_start + metric_dst->exp_hist_negative_count;
            src_start = metric_src->exp_hist_negative_offset;
            src_end = src_start + metric_src->exp_hist_negative_count;

            merged_start = dst_start < src_start ? dst_start : src_start;
            merged_end = dst_end > src_end ? dst_end : src_end;
            merged_count = (size_t) (merged_end - merged_start);

            merged_buckets = calloc(merged_count, sizeof(uint64_t));
            if (merged_buckets == NULL) {
                goto cleanup;
            }

            for (index = 0; index < metric_dst->exp_hist_negative_count; index++) {
                merged_buckets[(size_t) (dst_start + index - merged_start)] +=
                    metric_dst->exp_hist_negative_buckets[index];
            }

            for (index = 0; index < metric_src->exp_hist_negative_count; index++) {
                merged_buckets[(size_t) (src_start + index - merged_start)] +=
                    metric_src->exp_hist_negative_buckets[index];
            }

            tmp_buckets = metric_dst->exp_hist_negative_buckets;
            metric_dst->exp_hist_negative_buckets = merged_buckets;
            metric_dst->exp_hist_negative_offset = (int32_t) merged_start;
            metric_dst->exp_hist_negative_count = merged_count;
            free(tmp_buckets);
        }
    }

    metric_dst->exp_hist_zero_count += metric_src->exp_hist_zero_count;

    do {
        old_value = cmt_atomic_load(&metric_dst->exp_hist_count);
        new_value = old_value + cmt_atomic_load(&metric_src->exp_hist_count);
        result = cmt_atomic_compare_exchange(&metric_dst->exp_hist_count,
                                             old_value, new_value);
    }
    while (result == 0);

    if (cmt_atomic_load(&metric_dst->exp_hist_sum_set) &&
        cmt_atomic_load(&metric_src->exp_hist_sum_set)) {
        cmt_atomic_store(&metric_dst->exp_hist_sum,
                         cmt_math_d64_to_uint64(
                             cmt_math_uint64_to_d64(
                                 cmt_atomic_load(&metric_dst->exp_hist_sum)) +
                             cmt_math_uint64_to_d64(
                                 cmt_atomic_load(&metric_src->exp_hist_sum))));
    }
    else if (cmt_atomic_load(&metric_src->exp_hist_sum_set)) {
        cmt_atomic_store(&metric_dst->exp_hist_sum_set, CMT_TRUE);
        cmt_atomic_store(&metric_dst->exp_hist_sum,
                         cmt_atomic_load(&metric_src->exp_hist_sum));
    }

    result = 0;

cleanup:
    if (second_lock_target != first_lock_target) {
        cmt_metric_exp_hist_unlock(second_lock_target);
    }
    cmt_metric_exp_hist_unlock(first_lock_target);

    return result;
}

static inline void cat_scalar_value(struct cmt_metric *metric_dst,
                                    struct cmt_metric *metric_src)
{
    uint64_t ts;
    double val;

    ts = cmt_metric_get_timestamp(metric_src);

    if (cmt_metric_get_value_type(metric_src) == CMT_METRIC_VALUE_INT64) {
        cmt_metric_set_int64(metric_dst, ts, cmt_metric_get_int64_value(metric_src));
    }
    else if (cmt_metric_get_value_type(metric_src) == CMT_METRIC_VALUE_UINT64) {
        cmt_metric_set_uint64(metric_dst, ts, cmt_metric_get_uint64_value(metric_src));
    }
    else {
        val = cmt_metric_get_value(metric_src);
        cmt_metric_set_double(metric_dst, ts, val);
    }

    if (cmt_metric_has_start_timestamp(metric_src)) {
        cmt_metric_set_start_timestamp(metric_dst,
                                       cmt_metric_get_start_timestamp(metric_src));
    }
    else {
        cmt_metric_unset_start_timestamp(metric_dst);
    }
}

int cmt_cat_copy_map(struct cmt_opts *opts, struct cmt_map *dst, struct cmt_map *src)
{
    int c;
    int ret;
    char **labels = NULL;
    struct cfl_list *head;
    struct cmt_metric *metric_dst;
    struct cmt_metric *metric_src;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram_src;
    struct cmt_histogram *histogram_dst;

    /* Handle static metric (no labels case) */
    if (src->metric_static_set) {
        dst->metric_static_set = CMT_TRUE;

        /* destination and source metric */
        metric_dst = &dst->metric;
        metric_src = &src->metric;

        if (src->type == CMT_HISTOGRAM) {
            histogram_src = (struct cmt_histogram *) src->parent;
            histogram_dst = (struct cmt_histogram *) dst->parent;
            ret = cat_histogram_values(metric_dst, histogram_src, metric_src, histogram_dst);
            if (ret == -1) {
                return -1;
            }
        }
        else if (src->type == CMT_SUMMARY) {
            summary = (struct cmt_summary *) src->parent;
            ret = cat_summary_values(metric_dst, summary, metric_src);
            if (ret == -1) {
                return -1;
            }
        }
        else if (src->type == CMT_EXP_HISTOGRAM) {
            ret = cat_exp_histogram_values(metric_dst, metric_src);
            if (ret == -1) {
                return -1;
            }
        }

        cat_scalar_value(metric_dst, metric_src);
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
            histogram_src = (struct cmt_histogram *) src->parent;
            histogram_dst = (struct cmt_histogram *) dst->parent;
            ret = cat_histogram_values(metric_dst, histogram_src, metric_src, histogram_dst);
            if (ret == -1) {
                return -1;
            }
        }
        else if (src->type == CMT_SUMMARY) {
            summary = (struct cmt_summary *) src->parent;
            ret = cat_summary_values(metric_dst, summary, metric_src);
            if (ret == -1) {
                return -1;
            }
        }
        else if (src->type == CMT_EXP_HISTOGRAM) {
            ret = cat_exp_histogram_values(metric_dst, metric_src);
            if (ret == -1) {
                return -1;
            }
        }

        cat_scalar_value(metric_dst, metric_src);
    }

    return 0;

}

static inline int cmt_opts_compare(struct cmt_opts *a, struct cmt_opts *b)
{
    int ret;

    ret = strcmp(a->ns, b->ns);
    if (ret != 0) {
        return ret;
    }

    ret = strcmp(a->subsystem, b->subsystem);
    if (ret != 0) {
        return ret;
    }

    ret = strcmp(a->name, b->name);
    if (ret != 0) {
        return ret;
    }

    return strcmp(a->description, b->description);
}

static struct cmt_counter *counter_lookup(struct cmt *cmt, struct cmt_opts *opts)
{
    struct cmt_counter *counter;
    struct cfl_list *head;

    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        if (cmt_opts_compare(&counter->opts, opts) == 0) {
            return counter;
        }
    }

    return NULL;
}

static struct cmt_gauge *gauge_lookup(struct cmt *cmt, struct cmt_opts *opts)
{
    struct cmt_gauge *gauge;
    struct cfl_list *head;

    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        if (cmt_opts_compare(&gauge->opts, opts) == 0) {
            return gauge;
        }
    }

    return NULL;
}

static struct cmt_untyped *untyped_lookup(struct cmt *cmt, struct cmt_opts *opts)
{
    struct cmt_untyped *untyped;
    struct cfl_list *head;

    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        if (cmt_opts_compare(&untyped->opts, opts) == 0) {
            return untyped;
        }
    }

    return NULL;
}

static struct cmt_histogram *histogram_lookup(struct cmt *cmt, struct cmt_opts *opts)
{
    struct cmt_histogram *histogram;
    struct cfl_list *head;

    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        if (cmt_opts_compare(&histogram->opts, opts) == 0) {
            return histogram;
        }
    }

    return NULL;
}

static struct cmt_exp_histogram *exp_histogram_lookup(struct cmt *cmt, struct cmt_opts *opts)
{
    struct cmt_exp_histogram *exp_histogram;
    struct cfl_list *head;

    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        if (cmt_opts_compare(&exp_histogram->opts, opts) == 0) {
            return exp_histogram;
        }
    }

    return NULL;
}

int cmt_cat_counter(struct cmt *cmt, struct cmt_counter *counter,
                    struct cmt_map *filtered_map)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_counter *c;

    map = counter->map;
    opts = map->opts;

    ret = cmt_cat_copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    c = counter_lookup(cmt, opts);
    if (!c) {
        /* create counter */
        c = cmt_counter_create(cmt,
                            opts->ns, opts->subsystem,
                            opts->name, opts->description,
                            map->label_count, labels);
    }

    free(labels);
    if (!c) {
        return -1;
    }

    if (filtered_map != NULL) {
        ret = cmt_cat_copy_map(&c->opts, c->map, filtered_map);
        if (ret == -1) {
            return -1;
        }
    }
    else {
        ret = cmt_cat_copy_map(&c->opts, c->map, map);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int cmt_cat_gauge(struct cmt *cmt, struct cmt_gauge *gauge,
                  struct cmt_map *filtered_map)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_gauge *g;

    map = gauge->map;
    opts = map->opts;

    ret = cmt_cat_copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    g = gauge_lookup(cmt, opts);
    if (!g) {
        /* create counter */
        g = cmt_gauge_create(cmt,
                            opts->ns, opts->subsystem,
                            opts->name, opts->description,
                            map->label_count, labels);
    }

    free(labels);
    if (!g) {
        return -1;
    }

    if (filtered_map != NULL) {
        ret = cmt_cat_copy_map(&g->opts, g->map, filtered_map);
        if (ret == -1) {
            return -1;
        }
    }
    else {
        ret = cmt_cat_copy_map(&g->opts, g->map, map);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int cmt_cat_untyped(struct cmt *cmt, struct cmt_untyped *untyped,
                    struct cmt_map *filtered_map)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_untyped *u;

    map = untyped->map;
    opts = map->opts;

    ret = cmt_cat_copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    u = untyped_lookup(cmt, opts);
    if (!u) {
        /* create counter */
        u = cmt_untyped_create(cmt,
                            opts->ns, opts->subsystem,
                            opts->name, opts->description,
                            map->label_count, labels);
    }

    free(labels);
    if (!u) {
        return -1;
    }

    if (filtered_map != NULL) {
        ret = cmt_cat_copy_map(&u->opts, u->map, filtered_map);
        if (ret == -1) {
            return -1;
        }
    }
    else {
        ret = cmt_cat_copy_map(&u->opts, u->map, map);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int cmt_cat_histogram(struct cmt *cmt, struct cmt_histogram *histogram,
                      struct cmt_map *filtered_map)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_histogram *hist;
    struct cmt_histogram_buckets *buckets;
    int64_t buckets_count;

    map = histogram->map;
    opts = map->opts;

    ret = cmt_cat_copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    hist = histogram_lookup(cmt, opts);
    if (!hist) {
        buckets_count = histogram->buckets->count;
        buckets = cmt_histogram_buckets_create_size(histogram->buckets->upper_bounds,
                                                    buckets_count);

        /* create histogram */
        hist = cmt_histogram_create(cmt,
                                    opts->ns, opts->subsystem,
                                    opts->name, opts->description,
                                    buckets,
                                    map->label_count, labels);
    }
    free(labels);

    if (!hist) {
        return -1;
    }

    if (filtered_map != NULL) {
        ret = cmt_cat_copy_map(&hist->opts, hist->map, filtered_map);
        if (ret == -1) {
            return -1;
        }
    }
    else {
        ret = cmt_cat_copy_map(&hist->opts, hist->map, map);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int cmt_cat_summary(struct cmt *cmt, struct cmt_summary *summary,
                    struct cmt_map *filtered_map)
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

    ret = cmt_cat_copy_label_keys(map, (char **) &labels);
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
        free(labels);
        free(quantiles);
        return -1;
    }

    summary_sum = cmt_summary_get_sum_value(&summary->map->metric);

    cmt_summary_set_default(sum, timestamp, quantiles, summary_sum, summary->quantiles_count, map->label_count, labels);
    free(labels);
    free(quantiles);

    if (filtered_map != NULL) {
        ret = cmt_cat_copy_map(&sum->opts, sum->map, filtered_map);
        if (ret == -1) {
            return -1;
        }
    }
    else {
        ret = cmt_cat_copy_map(&sum->opts, sum->map, map);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int cmt_cat_exp_histogram(struct cmt *cmt, struct cmt_exp_histogram *exp_histogram,
                          struct cmt_map *filtered_map)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_exp_histogram *eh;

    map = exp_histogram->map;
    opts = map->opts;

    ret = cmt_cat_copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    eh = exp_histogram_lookup(cmt, opts);
    if (!eh) {
        eh = cmt_exp_histogram_create(cmt,
                                      opts->ns, opts->subsystem,
                                      opts->name, opts->description,
                                      map->label_count, labels);
    }

    free(labels);
    if (!eh) {
        return -1;
    }

    if (filtered_map != NULL) {
        ret = cmt_cat_copy_map(&eh->opts, eh->map, filtered_map);
    }
    else {
        ret = cmt_cat_copy_map(&eh->opts, eh->map, map);
    }

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
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;

     /* Counters */
    cfl_list_foreach(head, &src->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        ret = cmt_cat_counter(dst, counter, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Gauges */
    cfl_list_foreach(head, &src->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        ret = cmt_cat_gauge(dst, gauge, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Untyped */
    cfl_list_foreach(head, &src->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        ret = cmt_cat_untyped(dst, untyped, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Histogram */
    cfl_list_foreach(head, &src->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        ret = cmt_cat_histogram(dst, histogram, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Exponential Histogram */
    cfl_list_foreach(head, &src->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        ret = cmt_cat_exp_histogram(dst, exp_histogram, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Summary */
    cfl_list_foreach(head, &src->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        ret = cmt_cat_summary(dst, summary, NULL);
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
