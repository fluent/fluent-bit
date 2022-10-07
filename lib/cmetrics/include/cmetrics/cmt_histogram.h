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

#ifndef CMT_HISTOGRAM_H
#define CMT_HISTOGRAM_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_opts.h>

struct cmt_histogram_buckets {
    size_t count;
    double *upper_bounds;
};

struct cmt_histogram {
    struct cmt_histogram_buckets *buckets;
    struct cmt_opts opts;
    struct cmt_map *map;
    struct cfl_list _head;
    struct cmt *cmt;
    int    aggregation_type;
};

/* Buckets */
struct cmt_histogram_buckets *cmt_histogram_buckets_create_size(double *bkts, size_t count);
struct cmt_histogram_buckets *cmt_histogram_buckets_create(size_t count, ...);
void cmt_histogram_buckets_destroy(struct cmt_histogram_buckets *buckets);

struct cmt_histogram_buckets *cmt_histogram_buckets_default_create();
struct cmt_histogram_buckets *cmt_histogram_buckets_linear_create(double start,
                                                                  double width,
                                                                  size_t count);
struct cmt_histogram_buckets *cmt_histogram_buckets_exponential_create(double start,
                                                                       double factor,
                                                                       size_t count);
/* Histogram */
struct cmt_histogram *cmt_histogram_create(struct cmt *cmt,
                                           char *ns, char *subsystem,
                                           char *name, char *help,
                                           struct cmt_histogram_buckets *buckets,
                                           int label_count, char **label_keys);

int cmt_histogram_observe(struct cmt_histogram *histogram, uint64_t timestamp,
                          double val, int labels_count, char **label_vals);

int cmt_histogram_set_default(struct cmt_histogram *histogram,
                              uint64_t timestamp,
                              uint64_t *bucket_defaults,
                              double sum,
                              uint64_t count,
                              int labels_count, char **label_vals);

int cmt_histogram_destroy(struct cmt_histogram *h);

#endif
