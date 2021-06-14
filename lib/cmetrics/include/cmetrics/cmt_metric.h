/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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
    uint64_t val;
    uint64_t hash;
    uint64_t timestamp;
    struct mk_list labels;
    struct mk_list _head;
};

void cmt_metric_set(struct cmt_metric *metric, uint64_t timestamp, double val);
void cmt_metric_inc(struct cmt_metric *metric, uint64_t timestamp);
void cmt_metric_dec(struct cmt_metric *metric, uint64_t timestamp);
void cmt_metric_add(struct cmt_metric *metric, uint64_t timestamp, double val);
void cmt_metric_sub(struct cmt_metric *metric, uint64_t timestamp, double val);
double cmt_metric_get_value(struct cmt_metric *metric);
uint64_t cmt_metric_get_timestamp(struct cmt_metric *metric);

#endif
