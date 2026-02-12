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

    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_DOUBLE);
    cmt_atomic_store(&metric->val_int64, (uint64_t) ((int64_t) new));
    cmt_atomic_store(&metric->val_uint64, (uint64_t) new);
}

void cmt_metric_set(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    cmt_metric_set_double(metric, timestamp, val);
}

void cmt_metric_set_double(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    uint64_t tmp;

    tmp = cmt_math_d64_to_uint64(val);

    cmt_atomic_store(&metric->val, tmp);
    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_DOUBLE);
    cmt_atomic_store(&metric->val_int64, (uint64_t) ((int64_t) val));
    cmt_atomic_store(&metric->val_uint64, (uint64_t) val);
    cmt_atomic_store(&metric->timestamp, timestamp);
}

void cmt_metric_set_int64(struct cmt_metric *metric, uint64_t timestamp, int64_t val)
{
    uint64_t tmp;

    tmp = cmt_math_d64_to_uint64((double) val);

    cmt_atomic_store(&metric->val, tmp);
    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_INT64);
    cmt_atomic_store(&metric->val_int64, (uint64_t) val);
    cmt_atomic_store(&metric->val_uint64, (uint64_t) val);
    cmt_atomic_store(&metric->timestamp, timestamp);
}

void cmt_metric_set_uint64(struct cmt_metric *metric, uint64_t timestamp, uint64_t val)
{
    uint64_t tmp;

    tmp = cmt_math_d64_to_uint64((double) val);

    cmt_atomic_store(&metric->val, tmp);
    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_UINT64);
    cmt_atomic_store(&metric->val_int64, (uint64_t) ((int64_t) val));
    cmt_atomic_store(&metric->val_uint64, val);
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

int cmt_metric_get_value_type(struct cmt_metric *metric)
{
    return (int) cmt_atomic_load(&metric->value_type);
}

int64_t cmt_metric_get_int64_value(struct cmt_metric *metric)
{
    uint64_t value_type;

    value_type = cmt_atomic_load(&metric->value_type);

    if (value_type == CMT_METRIC_VALUE_INT64) {
        return (int64_t) cmt_atomic_load(&metric->val_int64);
    }

    if (value_type == CMT_METRIC_VALUE_UINT64) {
        return (int64_t) cmt_atomic_load(&metric->val_uint64);
    }

    return (int64_t) cmt_metric_get_value(metric);
}

uint64_t cmt_metric_get_uint64_value(struct cmt_metric *metric)
{
    uint64_t value_type;

    value_type = cmt_atomic_load(&metric->value_type);

    if (value_type == CMT_METRIC_VALUE_UINT64) {
        return cmt_atomic_load(&metric->val_uint64);
    }

    if (value_type == CMT_METRIC_VALUE_INT64) {
        return (uint64_t) ((int64_t) cmt_atomic_load(&metric->val_int64));
    }

    return (uint64_t) cmt_metric_get_value(metric);
}

void cmt_metric_get_value_snapshot(struct cmt_metric *metric,
                                   int *out_type,
                                   int64_t *out_int64,
                                   uint64_t *out_uint64)
{
    uint64_t type_first;
    uint64_t type_second;
    uint64_t int_value;
    uint64_t uint_value;

    do {
        type_first = cmt_atomic_load(&metric->value_type);
        int_value = cmt_atomic_load(&metric->val_int64);
        uint_value = cmt_atomic_load(&metric->val_uint64);
        type_second = cmt_atomic_load(&metric->value_type);
    }
    while (type_first != type_second);

    if (out_type != NULL) {
        *out_type = (int) type_first;
    }

    if (out_int64 != NULL) {
        *out_int64 = (int64_t) int_value;
    }

    if (out_uint64 != NULL) {
        *out_uint64 = uint_value;
    }
}

uint64_t cmt_metric_get_timestamp(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->timestamp);

    return val;
}
