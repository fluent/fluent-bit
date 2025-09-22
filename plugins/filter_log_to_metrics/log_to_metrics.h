/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_filter_plugin.h>
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

#define FLB_MEM_BUF_LIMIT_DEFAULT  "10M"
#define DEFAULT_LOG_TO_METRICS_NAMESPACE "log_metric"
#define DEFAULT_INTERVAL_SEC  "0"
#define DEFAULT_INTERVAL_NSEC "0"

struct log_to_metrics_ctx {
    struct mk_list rules;
    struct flb_filter_instance *ins;
    struct cmt *cmt;
    struct flb_input_instance *input_ins;

    char **label_keys;
    char **label_accessors;

    int label_counter;
    int bucket_counter;
    double *buckets;

    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *histogram_buckets;
    struct flb_record_accessor *value_ra;

    /* config options */
    int mode;
    flb_sds_t mode_name;
    int discard_logs;
    int kubernetes_mode;
    flb_sds_t metric_name;
    flb_sds_t metric_namespace;
    flb_sds_t metric_subsystem;
    flb_sds_t metric_description;
    flb_sds_t value_field;
    flb_sds_t tag;
    flb_sds_t emitter_name;
    size_t emitter_mem_buf_limit;
    long flush_interval_sec;
    long flush_interval_nsec;
    int timer_interval;
    int timer_mode;
    struct flb_sched_timer *timer;
    int new_data;
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
