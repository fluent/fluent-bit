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
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_histogram.h>

#include <stdarg.h>

struct cmt_histogram_buckets *cmt_histogram_buckets_create_size(double *bkts, size_t count)
{
    int i;
    double *upper_bounds;
    struct cmt_histogram_buckets *buckets;

    if (count < 1) {
        return NULL;
    }

    /* besides buckets set by the user, we add an implicit bucket for +inf */
    upper_bounds = calloc(1, sizeof(double) * count + 1);
    if (!upper_bounds) {
        cmt_errno();
        return NULL;
    }

    buckets = calloc(1, sizeof(struct cmt_histogram_buckets));
    if (!buckets) {
        cmt_errno();
        free(upper_bounds);
        return NULL;
    }

    buckets->count = count;
    buckets->upper_bounds = upper_bounds;

    if (bkts != NULL) {
        for (i = 0; i < count; i++) {
            upper_bounds[i] = bkts[i];
        }
    }

    return buckets;
}

struct cmt_histogram_buckets *cmt_histogram_buckets_create(size_t count, ...)
{
    int i;
    double *bucket_array;
    struct cmt_histogram_buckets *buckets;
    va_list va;

    bucket_array = calloc(count, sizeof(double));
    if (!bucket_array) {
        return NULL;
    }

    va_start(va, count);
    for (i = 0; i < count; i++) {
        bucket_array[i] = va_arg(va, double);
    }
    va_end(va);

    buckets = cmt_histogram_buckets_create_size(bucket_array, count);
    free(bucket_array);

    return buckets;
}

/* Create default buckets */
struct cmt_histogram_buckets *cmt_histogram_buckets_default_create()
{
    return cmt_histogram_buckets_create_size((double[]) {
                                        0.005, 0.01, 0.025, 0.05,
                                        0.1, 0.25, 0.5, 1.0, 2.5,
                                        5.0, 10.0 }, 11);
}

/* Linear bucket creation */
struct cmt_histogram_buckets *cmt_histogram_buckets_linear_create(double start,
                                                                  double width,
                                                                  size_t count)
{
    int i;
    double *upper_bounds;
    struct cmt_histogram_buckets *buckets;

    if (count <= 1) {
        return NULL;
    }

    upper_bounds = calloc(1, sizeof(double) * count);
    if (!upper_bounds) {
        cmt_errno();
        return NULL;
    }

    buckets = calloc(1, sizeof(struct cmt_histogram_buckets));
    if (!buckets) {
        cmt_errno();
        free(upper_bounds);
        return NULL;
    }

    buckets->count = count;
    buckets->upper_bounds = upper_bounds;

    /* initialize first bucket */
    upper_bounds[0] = start;

    for (i = 1; i < count; i++) {
        upper_bounds[i] = upper_bounds[i - 1] + width;
    }

    return buckets;
}

/* Exponential bucket creation */
struct cmt_histogram_buckets *cmt_histogram_buckets_exponential_create(double start,
                                                                       double factor,
                                                                       size_t count)
{
    int i;
    double *upper_bounds;
    struct cmt_histogram_buckets *buckets;

    if (start <= 0) {
        return NULL;
    }

    if (factor <= 1) {
        return NULL;
    }

    if (count < 1) {
        return NULL;
    }

    upper_bounds = calloc(1, sizeof(double) * count);
    if (!upper_bounds) {
        cmt_errno();
        return NULL;
    }

    buckets = calloc(1, sizeof(struct cmt_histogram_buckets));
    if (!buckets) {
        cmt_errno();
        free(upper_bounds);
        return NULL;
    }

    buckets->count = count;
    buckets->upper_bounds = upper_bounds;

    /* initialize first bucket */
    upper_bounds[0] = start;

    for (i = 1; i < count; i++) {
        upper_bounds[i] = upper_bounds[i - 1] * factor;
    }

    return buckets;
}

void cmt_histogram_buckets_destroy(struct cmt_histogram_buckets *buckets)
{
    if (!buckets) {
        return;
    }

    if (buckets->upper_bounds) {
        free(buckets->upper_bounds);
    }

    free(buckets);
}

static int check_buckets(struct cmt_histogram_buckets *buckets)
{
    int i;

    for (i = 1; i < buckets->count; i++) {
        if (buckets->upper_bounds[i - 1] > buckets->upper_bounds[i]) {
            return -1;
        }
    }

    return 0;
}

struct cmt_histogram *cmt_histogram_create(struct cmt *cmt,
                                           char *ns, char *subsystem,
                                           char *name, char *help,
                                           struct cmt_histogram_buckets *buckets,
                                           int label_count, char **label_keys)
{
    int ret;
    struct cmt_histogram *h;

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

    h = calloc(1, sizeof(struct cmt_histogram));
    if (!h) {
        cmt_errno();
        return NULL;
    }
    cfl_list_add(&h->_head, &cmt->histograms);

    /* set buckets */
    if (buckets) {
        h->buckets = buckets;
    }
    else {
        /* set 'default' buckets */
        h->buckets = cmt_histogram_buckets_default_create();
        if (!h->buckets) {
            cmt_histogram_destroy(h);
            return NULL;
        }
    }

    /* Validate buckets order */
    ret = check_buckets(h->buckets);
    if (ret != 0) {
        cmt_histogram_destroy(h);
        return NULL;
    }

    /* initialize options */
    ret = cmt_opts_init(&h->opts, ns, subsystem, name, help);
    if (ret == -1) {
        cmt_log_error(cmt, "unable to initialize options for histogram");
        cmt_histogram_destroy(h);
        return NULL;
    }

    /* Create the map */
    h->map = cmt_map_create(CMT_HISTOGRAM, &h->opts, label_count, label_keys,
                            (void *) h);
    if (!h->map) {
        cmt_log_error(cmt, "unable to allocate map for histogram");
        cmt_histogram_destroy(h);
        return NULL;
    }

    return h;
}

int cmt_histogram_destroy(struct cmt_histogram *h)
{
    cfl_list_del(&h->_head);
    cmt_opts_exit(&h->opts);

    if (h->buckets) {
        cmt_histogram_buckets_destroy(h->buckets);
    }

    if (h->map) {
        cmt_map_destroy(h->map);
    }

    free(h);
    return 0;
}

static struct cmt_metric *histogram_get_metric(struct cmt_histogram *histogram,
                                               int labels_count, char **label_vals)
{
    struct cmt_metric *metric;
    struct cmt_histogram_buckets *buckets;

    metric = cmt_map_metric_get(&histogram->opts, histogram->map,
                                labels_count, label_vals, CMT_TRUE);
    if (!metric) {
        cmt_log_error(histogram->cmt,
                      "unable to retrieve metric: %s for histogram %s_%s_%s",
                      histogram->map, histogram->opts.ns, histogram->opts.subsystem,
                      histogram->opts.name);
        return NULL;
    }

    /* ref buckets */
    buckets = histogram->buckets;

    /* make sure buckets has been initialized */
    if (!metric->hist_buckets) {
        metric->hist_buckets = calloc(1, sizeof(uint64_t) * (buckets->count + 1));
        if (!metric->hist_buckets) {
            cmt_errno();
            return NULL;
        }
    }

    return metric;
}

/* Observe the value and put it in the right bucket */
int cmt_histogram_observe(struct cmt_histogram *histogram, uint64_t timestamp,
                          double val, int labels_count, char **label_vals)
{
    int i;
    struct cmt_metric *metric;
    struct cmt_histogram_buckets *buckets;

    metric = histogram_get_metric(histogram, labels_count, label_vals);
    if (!metric) {
        cmt_log_error(histogram->cmt,
                      "unable to retrieve metric for histogram %s_%s_%s",
                      histogram->opts.ns, histogram->opts.subsystem,
                      histogram->opts.name);
        return -1;
    }

    /* increment buckets */
    buckets = histogram->buckets;
    for (i = buckets->count - 1; i >= 0; i--) {
        if (val > buckets->upper_bounds[i]) {
            break;
        }
        cmt_metric_hist_inc(metric, timestamp, i);
    }

    /* increment bucket +Inf */
    cmt_metric_hist_inc(metric, timestamp, buckets->count);

    /* increment bucket _count */
    cmt_metric_hist_count_inc(metric, timestamp);

    /* add observed value to _sum */
    cmt_metric_hist_sum_add(metric, timestamp, val);
    return 0;
}

int cmt_histogram_set_default(struct cmt_histogram *histogram,
                              uint64_t timestamp,
                              uint64_t *bucket_defaults,
                              double sum,
                              uint64_t count,
                              int labels_count, char **label_vals)
{
    int i;
    struct cmt_metric *metric;
    struct cmt_histogram_buckets *buckets;

    metric = histogram_get_metric(histogram, labels_count, label_vals);
    if (!metric) {
        cmt_log_error(histogram->cmt,
                      "unable to retrieve metric for histogram %s_%s_%s",
                      histogram->opts.ns, histogram->opts.subsystem,
                      histogram->opts.name);
        return -1;
    }

    /*
     * For every bucket, set the default value set in 'defaults', note that no
     * size check is performed and we trust the caller set the proper array size
     */
    buckets = histogram->buckets;
    for (i = 0; i <= buckets->count; i++) {
        cmt_metric_hist_set(metric, timestamp, i, bucket_defaults[i]);
    }

    cmt_metric_hist_sum_set(metric, timestamp, sum);
    cmt_metric_hist_count_set(metric, timestamp, count);

    return 0;
}
