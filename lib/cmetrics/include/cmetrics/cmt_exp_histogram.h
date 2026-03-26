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

#ifndef CMT_EXP_HISTOGRAM_H
#define CMT_EXP_HISTOGRAM_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_opts.h>
#include <cmetrics/cmt_metric.h>

struct cmt_exp_histogram {
    struct cmt_opts opts;
    struct cmt_map *map;
    struct cfl_list _head;
    struct cmt *cmt;
    int aggregation_type;
};

struct cmt_exp_histogram *cmt_exp_histogram_create(struct cmt *cmt,
                                                   char *ns, char *subsystem,
                                                   char *name, char *help,
                                                   int label_count, char **label_keys);

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
                                  int labels_count, char **label_vals);

int cmt_exp_histogram_destroy(struct cmt_exp_histogram *exp_histogram);

int cmt_exp_histogram_to_explicit(struct cmt_metric *metric,
                                  double **upper_bounds,
                                  size_t *upper_bounds_count,
                                  uint64_t **bucket_counts,
                                  size_t *bucket_count);

#endif
