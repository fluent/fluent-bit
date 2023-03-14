/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#ifndef FLB_FILTER_LOG_TO_METRICS_H
#define FLB_FILTER_LOG_TO_METRICS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>

/* rule types */
#define GREP_REGEX 1
#define GREP_EXCLUDE 2

/* actions */
#define GREP_RET_KEEP 0
#define GREP_RET_EXCLUDE 1

/* modes */
#define FLB_LOG_TO_METRICS_COUNTER_STR "counter"
#define FLB_LOG_TO_METRICS_GAUGE_STR "gauge"
#define FLB_LOG_TO_METRICS_HISTOGRAM_STR "histogram"


#define FLB_LOG_TO_METRICS_COUNTER 0
#define FLB_LOG_TO_METRICS_GAUGE 1
#define FLB_LOG_TO_METRICS_HISTOGRAM 2

#define NUMBER_OF_KUBERNETES_LABELS 5
#define MAX_LABEL_LENGTH 253
#define MAX_METRIC_LENGTH 253
#define MAX_LABEL_COUNT 32


struct log_to_metrics_ctx
{
    struct mk_list rules;
    struct flb_filter_instance *ins;
    int mode;
    flb_sds_t metric_name;
    flb_sds_t metric_description;
    struct cmt *cmt;
    struct flb_input_instance *input_ins;
    flb_sds_t value_field;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *histogram_buckets;
    char **label_keys;
    int *label_counter;
    bool kubernetes_mode;
    flb_sds_t tag;
    int *bucket_counter;
    double *buckets;
};

struct grep_rule
{
    int type;
    flb_sds_t field;
    char *regex_pattern;
    struct flb_regex *regex;
    struct flb_record_accessor *ra;
    struct mk_list _head;
};

#endif
