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

static inline int metric_exchange(struct cmt_metric *metric, uint64_t timestamp,
                                  double new_value, double old_value)
{
    uint64_t tmp_new;
    uint64_t tmp_old;
    int      result;

    tmp_new = cmt_math_d64_to_uint64(new_value);
    tmp_old = cmt_math_d64_to_uint64(old_value);

    result = cmt_atomic_compare_exchange(&metric->val, tmp_old, tmp_new);

    if(0 == result) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);

    return 1;
}

static inline void add(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    double   old;
    double   new;
    int      result;

    do {
        old = cmt_metric_get_value(metric);
        new = old + val;

        result = metric_exchange(metric, timestamp, new, old);
    }
    while(0 == result);
}

void cmt_metric_set(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    uint64_t tmp;

    tmp = cmt_math_d64_to_uint64(val);

    cmt_atomic_store(&metric->val, tmp);
    cmt_atomic_store(&metric->timestamp, timestamp);
}

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

void cmt_metric_hist_bucket_inc(struct cmt_metric *metric, uint64_t timestamp,
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


void cmt_metric_inc(struct cmt_metric *metric, uint64_t timestamp)
{
    add(metric, timestamp, 1);
}

void cmt_metric_dec(struct cmt_metric *metric, uint64_t timestamp)
{
    double volatile val = 1.0;

    add(metric, timestamp, val * -1);
}

void cmt_metric_add(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    add(metric, timestamp, val);
}

void cmt_metric_sub(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    add(metric, timestamp, (double volatile) val * -1);
}

double cmt_metric_get_value(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->val);

    return cmt_math_uint64_to_d64(val);
}

uint64_t cmt_metric_get_timestamp(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->timestamp);

    return val;
}
