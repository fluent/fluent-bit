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

struct cmt_metric {
    /* counters and gauges */
    uint64_t val;

    /* histogram */
    uint64_t *hist_buckets;
    uint64_t hist_count;
    uint64_t hist_sum;

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
void cmt_metric_inc(struct cmt_metric *metric, uint64_t timestamp);
void cmt_metric_dec(struct cmt_metric *metric, uint64_t timestamp);
void cmt_metric_add(struct cmt_metric *metric, uint64_t timestamp, double val);
void cmt_metric_sub(struct cmt_metric *metric, uint64_t timestamp, double val);
double cmt_metric_get_value(struct cmt_metric *metric);
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
