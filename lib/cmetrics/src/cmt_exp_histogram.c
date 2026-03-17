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

#include <math.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_math.h>
#include <cmetrics/cmt_exp_histogram.h>

static struct cmt_metric *exp_histogram_get_metric(struct cmt_exp_histogram *exp_histogram,
                                                   int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&exp_histogram->opts, exp_histogram->map,
                                labels_count, label_vals, CMT_TRUE);
    if (!metric) {
        cmt_log_error(exp_histogram->cmt,
                      "unable to retrieve metric for exponential histogram %s_%s_%s",
                      exp_histogram->opts.ns, exp_histogram->opts.subsystem,
                      exp_histogram->opts.name);
        return NULL;
    }

    return metric;
}

struct cmt_exp_histogram *cmt_exp_histogram_create(struct cmt *cmt,
                                                   char *ns, char *subsystem,
                                                   char *name, char *help,
                                                   int label_count, char **label_keys)
{
    int ret;
    struct cmt_exp_histogram *h;

    if (!ns) {
        cmt_log_error(cmt, "null ns not allowed");
        return NULL;
    }

    if (!subsystem) {
        cmt_log_error(cmt, "null subsystem not allowed");
        return NULL;
    }

    if (!name || strlen(name) == 0) {
        cmt_log_error(cmt, "undefined name");
        return NULL;
    }

    if (!help || strlen(help) == 0) {
        cmt_log_error(cmt, "undefined help");
        return NULL;
    }

    h = calloc(1, sizeof(struct cmt_exp_histogram));
    if (!h) {
        cmt_errno();
        return NULL;
    }

    cfl_list_add(&h->_head, &cmt->exp_histograms);

    ret = cmt_opts_init(&h->opts, ns, subsystem, name, help);
    if (ret == -1) {
        cmt_log_error(cmt, "unable to initialize options for exponential histogram");
        cmt_exp_histogram_destroy(h);
        return NULL;
    }

    h->map = cmt_map_create(CMT_EXP_HISTOGRAM, &h->opts, label_count, label_keys, (void *) h);
    if (!h->map) {
        cmt_log_error(cmt, "unable to allocate map for exponential histogram");
        cmt_exp_histogram_destroy(h);
        return NULL;
    }

    h->cmt = cmt;

    return h;
}

int cmt_exp_histogram_set_default(struct cmt_exp_histogram *exp_histogram,
                                  uint64_t timestamp,
                                  int32_t scale,
                                  uint64_t zero_count,
                                  double zero_threshold,
                                  int32_t positive_offset,
                                  size_t positive_bucket_count,
                                  uint64_t *positive_bucket_counts,
                                  int32_t negative_offset,
                                  size_t negative_bucket_count,
                                  uint64_t *negative_bucket_counts,
                                  int sum_set,
                                  double sum,
                                  uint64_t count,
                                  int labels_count, char **label_vals)
{
    struct cmt_metric *metric;
    uint64_t *new_positive_buckets;
    uint64_t *new_negative_buckets;

    metric = exp_histogram_get_metric(exp_histogram, labels_count, label_vals);
    if (!metric) {
        return -1;
    }

    new_positive_buckets = NULL;
    new_negative_buckets = NULL;

    if (positive_bucket_count > 0 && positive_bucket_counts != NULL) {
        new_positive_buckets = calloc(positive_bucket_count, sizeof(uint64_t));
        if (new_positive_buckets == NULL) {
            return -1;
        }

        memcpy(new_positive_buckets, positive_bucket_counts,
               sizeof(uint64_t) * positive_bucket_count);
    }

    if (negative_bucket_count > 0 && negative_bucket_counts != NULL) {
        new_negative_buckets = calloc(negative_bucket_count, sizeof(uint64_t));
        if (new_negative_buckets == NULL) {
            if (new_positive_buckets != NULL) {
                free(new_positive_buckets);
            }
            return -1;
        }

        memcpy(new_negative_buckets, negative_bucket_counts,
               sizeof(uint64_t) * negative_bucket_count);
    }
    else if (negative_bucket_count > 0 && negative_bucket_counts == NULL) {
        if (new_positive_buckets != NULL) {
            free(new_positive_buckets);
        }
        return -1;
    }

    if (positive_bucket_count > 0 && positive_bucket_counts == NULL) {
        if (new_positive_buckets != NULL) {
            free(new_positive_buckets);
        }
        if (new_negative_buckets != NULL) {
            free(new_negative_buckets);
        }
        return -1;
    }

    if (metric->exp_hist_positive_buckets != NULL) {
        free(metric->exp_hist_positive_buckets);
    }
    if (metric->exp_hist_negative_buckets != NULL) {
        free(metric->exp_hist_negative_buckets);
    }

    metric->exp_hist_positive_buckets = new_positive_buckets;
    metric->exp_hist_negative_buckets = new_negative_buckets;
    metric->exp_hist_positive_count = positive_bucket_count;
    metric->exp_hist_negative_count = negative_bucket_count;

    metric->exp_hist_scale = scale;
    metric->exp_hist_zero_count = zero_count;
    metric->exp_hist_zero_threshold = zero_threshold;
    metric->exp_hist_positive_offset = positive_offset;
    metric->exp_hist_negative_offset = negative_offset;
    metric->exp_hist_count = count;
    metric->exp_hist_sum_set = sum_set ? CMT_TRUE : CMT_FALSE;
    metric->exp_hist_sum = cmt_math_d64_to_uint64(sum);
    metric->timestamp = timestamp;

    return 0;
}

int cmt_exp_histogram_destroy(struct cmt_exp_histogram *exp_histogram)
{
    cfl_list_del(&exp_histogram->_head);
    cmt_opts_exit(&exp_histogram->opts);

    if (exp_histogram->map) {
        cmt_map_destroy(exp_histogram->map);
    }

    free(exp_histogram);

    return 0;
}

int cmt_exp_histogram_to_explicit(struct cmt_metric *metric,
                                  double **upper_bounds,
                                  size_t *upper_bounds_count,
                                  uint64_t **bucket_counts,
                                  size_t *bucket_count)
{
    double    base;
    double   *local_upper_bounds;
    uint64_t *local_bucket_counts;
    uint64_t  cumulative_count;
    size_t    local_upper_bounds_count;
    size_t    local_bucket_count;
    size_t    index;
    size_t    target_index;
    int64_t   bucket_index;
    int       include_zero_threshold;

    if (metric == NULL ||
        upper_bounds == NULL ||
        upper_bounds_count == NULL ||
        bucket_counts == NULL ||
        bucket_count == NULL) {
        return -1;
    }

    base = pow(2.0, pow(2.0, (double) -metric->exp_hist_scale));
    if (!isfinite(base) || base <= 1.0) {
        return -1;
    }

    include_zero_threshold = (metric->exp_hist_zero_count > 0 ||
                              metric->exp_hist_zero_threshold > 0.0 ||
                              (metric->exp_hist_negative_count > 0 && metric->exp_hist_positive_count > 0) ||
                              (metric->exp_hist_negative_count == 0 && metric->exp_hist_positive_count == 0));

    local_upper_bounds_count = metric->exp_hist_negative_count + metric->exp_hist_positive_count;

    if (include_zero_threshold) {
        local_upper_bounds_count += (metric->exp_hist_zero_threshold > 0.0) ? 3 : 1;
    }

    local_bucket_count = local_upper_bounds_count + 1;

    local_upper_bounds = calloc(local_upper_bounds_count, sizeof(double));
    if (local_upper_bounds == NULL) {
        return -1;
    }

    local_bucket_counts = calloc(local_bucket_count, sizeof(uint64_t));
    if (local_bucket_counts == NULL) {
        free(local_upper_bounds);
        return -1;
    }

    target_index = 0;
    cumulative_count = 0;

    for (index = metric->exp_hist_negative_count ; index > 0 ; index--) {
        bucket_index = (int64_t) metric->exp_hist_negative_offset + (int64_t) index - 1;

        local_upper_bounds[target_index] = -pow(base, (double) bucket_index);
        if (!isfinite(local_upper_bounds[target_index])) {
            free(local_bucket_counts);
            free(local_upper_bounds);
            return -1;
        }

        cumulative_count += metric->exp_hist_negative_buckets[index - 1];
        local_bucket_counts[target_index] = cumulative_count;
        target_index++;
    }

    if (include_zero_threshold) {
        if (metric->exp_hist_zero_threshold > 0.0) {
            local_upper_bounds[target_index] = -metric->exp_hist_zero_threshold;
            local_bucket_counts[target_index] = cumulative_count;
            target_index++;

            cumulative_count += metric->exp_hist_zero_count;

            local_upper_bounds[target_index] = 0.0;
            local_bucket_counts[target_index] = cumulative_count;
            target_index++;

            local_upper_bounds[target_index] = metric->exp_hist_zero_threshold;
            local_bucket_counts[target_index] = cumulative_count;
            target_index++;
        }
        else {
            cumulative_count += metric->exp_hist_zero_count;
            local_upper_bounds[target_index] = 0.0;
            local_bucket_counts[target_index] = cumulative_count;
            target_index++;
        }
    }

    for (index = 0 ; index < metric->exp_hist_positive_count ; index++) {
        bucket_index = (int64_t) metric->exp_hist_positive_offset + (int64_t) index + 1;

        local_upper_bounds[target_index] = pow(base, (double) bucket_index);
        if (!isfinite(local_upper_bounds[target_index])) {
            free(local_bucket_counts);
            free(local_upper_bounds);
            return -1;
        }

        cumulative_count += metric->exp_hist_positive_buckets[index];
        local_bucket_counts[target_index] = cumulative_count;
        target_index++;
    }

    local_bucket_counts[local_bucket_count - 1] = metric->exp_hist_count;

    *upper_bounds = local_upper_bounds;
    *upper_bounds_count = local_upper_bounds_count;
    *bucket_counts = local_bucket_counts;
    *bucket_count = local_bucket_count;

    return 0;
}
