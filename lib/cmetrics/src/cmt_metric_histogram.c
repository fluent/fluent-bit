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
#include <cmetrics/cmt_math.h>
#include <cmetrics/cmt_atomic.h>

static inline int metric_hist_exchange(struct cmt_metric *metric,
                                       uint64_t timestamp,
                                       int bucket_id,
                                       uint64_t new, uint64_t old)
{
    int result;

    result = cmt_atomic_compare_exchange(&metric->hist_buckets[bucket_id],
                                         old, new);
    if (result == 0) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);
    return 1;
}

static inline int metric_hist_count_exchange(struct cmt_metric *metric,
                                             uint64_t timestamp,
                                             uint64_t new, uint64_t old)
{
    int result;

    result = cmt_atomic_compare_exchange(&metric->hist_count, old, new);
    if (result == 0) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);
    return 1;
}

static inline int metric_sum_exchange(struct cmt_metric *metric,
                                      uint64_t timestamp,
                                      double new_value, double old_value)
{
    uint64_t tmp_new;
    uint64_t tmp_old;
    int      result;

    tmp_new = cmt_math_d64_to_uint64(new_value);
    tmp_old = cmt_math_d64_to_uint64(old_value);

    result = cmt_atomic_compare_exchange(&metric->hist_sum, tmp_old, tmp_new);

    if (result == 0) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);
    return 1;
}

void cmt_metric_hist_inc(struct cmt_metric *metric, uint64_t timestamp,
                         int bucket_id)
{
    int result;
    uint64_t old;
    uint64_t new;

    do {
        old = cmt_atomic_load(&metric->hist_buckets[bucket_id]);
        new = old + 1;
        result = metric_hist_exchange(metric, timestamp, bucket_id, new, old);
    }
    while (result == 0);
}

void cmt_metric_hist_count_inc(struct cmt_metric *metric, uint64_t timestamp)
{
    int result;
    uint64_t old;
    uint64_t new;

    do {
        old = cmt_atomic_load(&metric->hist_count);
        new = old + 1;

        result = metric_hist_count_exchange(metric, timestamp, new, old);
    }
    while (result == 0);
}

void cmt_metric_hist_count_set(struct cmt_metric *metric, uint64_t timestamp,
                               uint64_t count)
{
    int result;
    uint64_t old;
    uint64_t new;

    do {
        old = cmt_atomic_load(&metric->hist_count);
        new = count;

        result = metric_hist_count_exchange(metric, timestamp, new, old);
    }
    while (result == 0);
}

void cmt_metric_hist_sum_add(struct cmt_metric *metric, uint64_t timestamp,
                             double val)
{
    double   old;
    double   new;
    int      result;

    do {
        old = cmt_metric_hist_get_sum_value(metric);
        new = old + val;
        result = metric_sum_exchange(metric, timestamp, new, old);
    }
    while (0 == result);
}

void cmt_metric_hist_sum_set(struct cmt_metric *metric, uint64_t timestamp,
                             double val)
{
    double   old;
    double   new;
    int      result;

    do {
        old = cmt_metric_hist_get_sum_value(metric);
        new = val;
        result = metric_sum_exchange(metric, timestamp, new, old);
    }
    while (0 == result);
}

void cmt_metric_hist_set(struct cmt_metric *metric, uint64_t timestamp,
                         int bucket_id, double val)
{
    int result;
    uint64_t old;
    uint64_t new;

    do {
        old = cmt_atomic_load(&metric->hist_buckets[bucket_id]);
        new = val;

        result = metric_hist_exchange(metric, timestamp, bucket_id, new, old);
    }
    while (result == 0);
}

uint64_t cmt_metric_hist_get_value(struct cmt_metric *metric, int bucket_id)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->hist_buckets[bucket_id]);
    return val;
}

uint64_t cmt_metric_hist_get_count_value(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->hist_count);
    return val;
}

double cmt_metric_hist_get_sum_value(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->hist_sum);
    return cmt_math_uint64_to_d64(val);
}
