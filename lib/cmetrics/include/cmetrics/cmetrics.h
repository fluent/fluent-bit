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

#ifndef CMT_H
#define CMT_H

#define CMT_FALSE     0
#define CMT_TRUE      !CMT_FALSE

#define CMT_COUNTER   0
#define CMT_GAUGE     1
#define CMT_HISTOGRAM 2
#define CMT_SUMMARY   3
#define CMT_UNTYPED   4
#define CMT_EXP_HISTOGRAM 5

#define CMT_AGGREGATION_TYPE_UNSPECIFIED 0
#define CMT_AGGREGATION_TYPE_DELTA       1
#define CMT_AGGREGATION_TYPE_CUMULATIVE  2

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <cfl/cfl.h>

#include <cmetrics/cmt_info.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_math.h>
#include <cmetrics/cmt_time.h>
#include <cmetrics/cmt_label.h>
#include <cmetrics/cmt_version.h>

struct cmt {
    /* logging */
    int log_level;
    void (*log_cb)(void *, int, const char *, int, const char *);

    /* cmetrics metadata */
    struct cfl_kvlist *internal_metadata;

    /* third party metadata (ie. otlp resource & instrumentation library) */
    struct cfl_kvlist *external_metadata;

    /* static labels */
    struct cmt_labels *static_labels;

    /* Metrics list */
    struct cfl_list counters;
    struct cfl_list gauges;
    struct cfl_list histograms;
    struct cfl_list exp_histograms;
    struct cfl_list summaries;
    struct cfl_list untypeds;

    /* Only used by the otlp decoder */
    struct cfl_list _head;
};

void cmt_initialize();

struct cmt *cmt_create();
void cmt_destroy(struct cmt *cmt);
int cmt_label_add(struct cmt *cmt, char *key, char *val);
char *cmt_version();

#endif
