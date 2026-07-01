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
#include <stdlib.h>
#include <string.h>

static inline int metric_exchange(struct cmt_metric *metric,
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

        result = metric_exchange(metric, new, old);
    }
    while(0 == result);

    cmt_atomic_store(&metric->val_int64, (uint64_t) ((int64_t) new));
    cmt_atomic_store(&metric->val_uint64, (uint64_t) new);
    cmt_atomic_store(&metric->timestamp, timestamp);
    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_DOUBLE);
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
    cmt_atomic_store(&metric->val_int64, (uint64_t) ((int64_t) val));
    cmt_atomic_store(&metric->val_uint64, (uint64_t) val);
    cmt_atomic_store(&metric->timestamp, timestamp);
    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_DOUBLE);
}

void cmt_metric_set_int64(struct cmt_metric *metric, uint64_t timestamp, int64_t val)
{
    uint64_t tmp;

    tmp = cmt_math_d64_to_uint64((double) val);

    cmt_atomic_store(&metric->val, tmp);
    cmt_atomic_store(&metric->val_int64, (uint64_t) val);
    cmt_atomic_store(&metric->val_uint64, (uint64_t) val);
    cmt_atomic_store(&metric->timestamp, timestamp);
    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_INT64);
}

void cmt_metric_set_uint64(struct cmt_metric *metric, uint64_t timestamp, uint64_t val)
{
    uint64_t tmp;

    tmp = cmt_math_d64_to_uint64((double) val);

    cmt_atomic_store(&metric->val, tmp);
    cmt_atomic_store(&metric->val_int64, (uint64_t) ((int64_t) val));
    cmt_atomic_store(&metric->val_uint64, val);
    cmt_atomic_store(&metric->timestamp, timestamp);
    cmt_atomic_store(&metric->value_type, CMT_METRIC_VALUE_UINT64);
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

void cmt_metric_set_timestamp(struct cmt_metric *metric, uint64_t timestamp)
{
    cmt_atomic_store(&metric->timestamp, timestamp);
}

void cmt_metric_set_start_timestamp(struct cmt_metric *metric, uint64_t start_timestamp)
{
    cmt_atomic_store(&metric->start_timestamp, start_timestamp);
    cmt_atomic_store(&metric->start_timestamp_set, 1);
}

void cmt_metric_unset_start_timestamp(struct cmt_metric *metric)
{
    cmt_atomic_store(&metric->start_timestamp, 0);
    cmt_atomic_store(&metric->start_timestamp_set, 0);
}

int cmt_metric_has_start_timestamp(struct cmt_metric *metric)
{
    return cmt_atomic_load(&metric->start_timestamp_set) != 0;
}

uint64_t cmt_metric_get_start_timestamp(struct cmt_metric *metric)
{
    return cmt_atomic_load(&metric->start_timestamp);
}

void cmt_metric_set_exp_hist_count(struct cmt_metric *metric, uint64_t count)
{
    cmt_atomic_store(&metric->exp_hist_count, count);
}

void cmt_metric_set_exp_hist_sum(struct cmt_metric *metric, int sum_set, double sum)
{
    cmt_atomic_store(&metric->exp_hist_sum_set, sum_set ? CMT_TRUE : CMT_FALSE);

    if (sum_set) {
        cmt_atomic_store(&metric->exp_hist_sum, cmt_math_d64_to_uint64(sum));
    }
    else {
        cmt_atomic_store(&metric->exp_hist_sum, 0);
    }
}

void cmt_metric_exp_hist_lock(struct cmt_metric *metric)
{
    while (cmt_atomic_compare_exchange(&metric->exp_hist_lock, 0, 1) == 0) {
    }
}

void cmt_metric_exp_hist_unlock(struct cmt_metric *metric)
{
    cmt_atomic_store(&metric->exp_hist_lock, 0);
}

int cmt_metric_exp_hist_get_snapshot(struct cmt_metric *metric,
                                     struct cmt_exp_histogram_snapshot *snapshot)
{
    if (metric == NULL || snapshot == NULL) {
        return -1;
    }

    memset(snapshot, 0, sizeof(struct cmt_exp_histogram_snapshot));

    cmt_metric_exp_hist_lock(metric);

    snapshot->scale = metric->exp_hist_scale;
    snapshot->zero_count = metric->exp_hist_zero_count;
    snapshot->zero_threshold = metric->exp_hist_zero_threshold;
    snapshot->positive_offset = metric->exp_hist_positive_offset;
    snapshot->positive_count = metric->exp_hist_positive_count;
    snapshot->negative_offset = metric->exp_hist_negative_offset;
    snapshot->negative_count = metric->exp_hist_negative_count;
    snapshot->count = cmt_atomic_load(&metric->exp_hist_count);
    snapshot->sum_set = cmt_atomic_load(&metric->exp_hist_sum_set);
    snapshot->sum = cmt_atomic_load(&metric->exp_hist_sum);

    if (snapshot->positive_count > 0) {
        if (metric->exp_hist_positive_buckets == NULL) {
            cmt_metric_exp_hist_unlock(metric);
            return -1;
        }

        snapshot->positive_buckets = calloc(snapshot->positive_count,
                                            sizeof(uint64_t));
        if (snapshot->positive_buckets == NULL) {
            cmt_metric_exp_hist_unlock(metric);
            return -1;
        }

        memcpy(snapshot->positive_buckets, metric->exp_hist_positive_buckets,
               sizeof(uint64_t) * snapshot->positive_count);
    }

    if (snapshot->negative_count > 0) {
        if (metric->exp_hist_negative_buckets == NULL) {
            free(snapshot->positive_buckets);
            snapshot->positive_buckets = NULL;
            cmt_metric_exp_hist_unlock(metric);
            return -1;
        }

        snapshot->negative_buckets = calloc(snapshot->negative_count,
                                            sizeof(uint64_t));
        if (snapshot->negative_buckets == NULL) {
            free(snapshot->positive_buckets);
            snapshot->positive_buckets = NULL;
            cmt_metric_exp_hist_unlock(metric);
            return -1;
        }

        memcpy(snapshot->negative_buckets, metric->exp_hist_negative_buckets,
               sizeof(uint64_t) * snapshot->negative_count);
    }

    cmt_metric_exp_hist_unlock(metric);

    return 0;
}

void cmt_metric_exp_hist_snapshot_destroy(struct cmt_exp_histogram_snapshot *snapshot)
{
    if (snapshot == NULL) {
        return;
    }

    if (snapshot->positive_buckets != NULL) {
        free(snapshot->positive_buckets);
        snapshot->positive_buckets = NULL;
    }

    if (snapshot->negative_buckets != NULL) {
        free(snapshot->negative_buckets);
        snapshot->negative_buckets = NULL;
    }
}
