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

#ifndef CMT_COUNTER_H
#define CMT_COUNTER_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_opts.h>

struct cmt_counter {
    struct cmt_opts opts;
    struct cmt_map *map;
    struct cfl_list _head;
    struct cmt *cmt;
    int    allow_reset;
    int    aggregation_type;
};

struct cmt_counter *cmt_counter_create(struct cmt *cmt,
                                       char *ns, char *subsystem,
                                       char *name, char *help,
                                       int label_count, char **label_keys);
void cmt_counter_allow_reset(struct cmt_counter *counter);
int cmt_counter_destroy(struct cmt_counter *counter);
int cmt_counter_inc(struct cmt_counter *counter, uint64_t timestamp,
                    int labels_count, char **label_vals);
int cmt_counter_add(struct cmt_counter *counter, uint64_t timestamp,
                    double val, int labels_count, char **label_vals);
int cmt_counter_set(struct cmt_counter *counter, uint64_t timestamp, double val,
                    int labels_count, char **label_vals);
int cmt_counter_get_val(struct cmt_counter *counter,
                        int labels_count, char **label_vals, double *out_val);
#endif

