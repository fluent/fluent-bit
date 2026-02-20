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

#ifndef CMT_SUMMARY_H
#define CMT_SUMMARY_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_opts.h>
#include <cmetrics/cmt_metric.h>

/*
 * The structure only is aware about final 'quantile' values, not percentiles or
 * any other involved variable. We won't do calculations.
 */
struct cmt_summary {
    /* summary specific */
    double *quantiles;
    size_t quantiles_count;

    /* metrics common */
    struct cmt_opts opts;
    struct cmt_map *map;
    struct cfl_list _head;
    struct cmt *cmt;

};

struct cmt_summary *cmt_summary_create(struct cmt *cmt,
                                       char *ns, char *subsystem,
                                       char *name, char *help,
                                       size_t quantiles_count,
                                       double *quantiles,
                                       int label_count, char **label_keys);

int cmt_summary_destroy(struct cmt_summary *summary);

int cmt_summary_set_default(struct cmt_summary *summary,
                            uint64_t timestamp,
                            double *quantile_values,
                            double sum,
                            uint64_t count,
                            int labels_count, char **label_vars);

/* quantiles */
double cmt_summary_quantile_get_value(struct cmt_metric *metric, int quantile_id);

double cmt_summary_get_sum_value(struct cmt_metric *metric);
uint64_t cmt_summary_get_count_value(struct cmt_metric *metric);

void cmt_summary_quantile_set(struct cmt_metric *metric, uint64_t timestamp,
                              int quantile_id, double val);
void cmt_summary_sum_set(struct cmt_metric *metric, uint64_t timestamp,
                         double val);
void cmt_summary_count_set(struct cmt_metric *metric, uint64_t timestamp,
                           uint64_t count);


#endif
