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

#ifndef CMT_METRIC_H
#define CMT_METRIC_H

#include <cmetrics/cmetrics.h>
#include <stdint.h>

enum cmt_metric_value_type {
    CMT_METRIC_VALUE_DOUBLE = 0,
    CMT_METRIC_VALUE_INT64  = 1,
    CMT_METRIC_VALUE_UINT64 = 2
};

struct cmt_metric {
    /* counters and gauges */
    uint64_t val;
    uint64_t value_type;
    uint64_t val_int64;
    uint64_t val_uint64;

    /* histogram */
    uint64_t *hist_buckets;
    uint64_t hist_count;
    uint64_t hist_sum;

    /* exponential histogram */
    int exp_hist_sum_set;
    int32_t exp_hist_scale;
    uint64_t exp_hist_zero_count;
    double exp_hist_zero_threshold;
    int32_t exp_hist_positive_offset;
    uint64_t *exp_hist_positive_buckets;
    size_t exp_hist_positive_count;
    int32_t exp_hist_negative_offset;
    uint64_t *exp_hist_negative_buckets;
    size_t exp_hist_negative_count;
    uint64_t exp_hist_count;
    uint64_t exp_hist_sum;

    /* summary */
    int sum_quantiles_set;     /* specify if quantive values has been set */
    uint64_t *sum_quantiles;   /* 0, 0.25, 0.5, 0.75 and 1 */
    size_t sum_quantiles_count;
    uint64_t sum_count;
    uint64_t sum_sum;

    /* internal */
    uint64_t hash;
    uint64_t timestamp;
    struct cfl_list labels;
    struct cfl_list _head;
};

void cmt_metric_set(struct cmt_metric *metric, uint64_t timestamp, double val);
void cmt_metric_set_double(struct cmt_metric *metric, uint64_t timestamp, double val);
void cmt_metric_set_int64(struct cmt_metric *metric, uint64_t timestamp, int64_t val);
void cmt_metric_set_uint64(struct cmt_metric *metric, uint64_t timestamp, uint64_t val);
void cmt_metric_inc(struct cmt_metric *metric, uint64_t timestamp);
void cmt_metric_dec(struct cmt_metric *metric, uint64_t timestamp);
void cmt_metric_add(struct cmt_metric *metric, uint64_t timestamp, double val);
void cmt_metric_sub(struct cmt_metric *metric, uint64_t timestamp, double val);
double cmt_metric_get_value(struct cmt_metric *metric);
int cmt_metric_get_value_type(struct cmt_metric *metric);
int64_t cmt_metric_get_int64_value(struct cmt_metric *metric);
uint64_t cmt_metric_get_uint64_value(struct cmt_metric *metric);
void cmt_metric_get_value_snapshot(struct cmt_metric *metric,
                                   int *out_type,
                                   int64_t *out_int64,
                                   uint64_t *out_uint64);
uint64_t cmt_metric_get_timestamp(struct cmt_metric *metric);

void cmt_metric_hist_inc(struct cmt_metric *metric, uint64_t timestamp,
                         int bucket_id);

void cmt_metric_hist_count_inc(struct cmt_metric *metric, uint64_t timestamp);
void cmt_metric_hist_count_set(struct cmt_metric *metric, uint64_t timestamp,
                               uint64_t count);

void cmt_metric_hist_sum_add(struct cmt_metric *metric, uint64_t timestamp,
                             double val);
void cmt_metric_hist_set(struct cmt_metric *metric, uint64_t timestamp,
                         int bucket_id, double val);

uint64_t cmt_metric_hist_get_value(struct cmt_metric *metric, int bucket_id);

double cmt_metric_hist_get_sum_value(struct cmt_metric *metric);

uint64_t cmt_metric_hist_get_count_value(struct cmt_metric *metric);

void cmt_metric_hist_sum_add(struct cmt_metric *metric,
                             uint64_t timestamp, double val);
void cmt_metric_hist_sum_set(struct cmt_metric *metric, uint64_t timestamp,
                             double val);

#endif
