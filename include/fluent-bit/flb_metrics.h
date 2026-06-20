/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <monkey/mk_core.h>

#ifdef FLB_HAVE_METRICS
#ifndef FLB_METRICS_H
#define FLB_METRICS_H

/* CMetrics */
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_influx.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_encode_splunk_hec.h>
#include <cmetrics/cmt_encode_cloudwatch_emf.h>
#include <cmetrics/cmt_decode_statsd.h>
#include <cmetrics/cmt_filter.h>

/*
 * v1 HTTP endpoint metrics
 * ------------------------
 * These are functions that are not part of the CMetrics library, its' the old interface
 * to ship internal metrics which is part of the v1 HTTP endpoint.
 */

/* Metrics IDs for general purpose (used by core and Plugins */
#define FLB_METRIC_N_RECORDS       0
#define FLB_METRIC_N_BYTES         1
#define FLB_METRIC_N_DROPPED       2
#define FLB_METRIC_N_ADDED         3
#define FLB_METRIC_N_DROPPED_BYTES 4

/* Genaral output plugin metrics */
#define FLB_METRIC_OUT_OK_RECORDS      10       /* proc_records   */
#define FLB_METRIC_OUT_OK_BYTES        11       /* proc_bytes     */
#define FLB_METRIC_OUT_ERROR           12       /* errors         */
#define FLB_METRIC_OUT_RETRY           13       /* retries        */
#define FLB_METRIC_OUT_RETRY_FAILED    14       /* retries_failed */
#define FLB_METRIC_OUT_DROPPED_RECORDS 15       /* dropped_records_total */
#define FLB_METRIC_OUT_RETRIED_RECORDS 16       /* retried_records_total */

/* The limitation of title name length */
#define FLB_METRIC_LENGTH_LIMIT 1024

struct flb_metric {
    int id;
    flb_sds_t title;
    size_t val;
    struct mk_list _head;
};

struct flb_metrics {
    int count;             /* Total count of metrics registered */
    flb_sds_t title;
    struct mk_list list;   /* Head of metrics list */
};

struct flb_metrics *flb_metrics_create(const char *title);
int flb_metrics_title(const char *title, struct flb_metrics *metrics);

struct flb_metric *flb_metrics_get_id(int id, struct flb_metrics *metrics);
int flb_metrics_add(int id, const char *title, struct flb_metrics *metrics);
int flb_metrics_sum(int id, size_t val, struct flb_metrics *metrics);
int flb_metrics_print(struct flb_metrics *metrics);
int flb_metrics_dump_values(char **out_buf, size_t *out_size,
                            struct flb_metrics *me);
int flb_metrics_destroy(struct flb_metrics *metrics);
int flb_metrics_fluentbit_add(struct flb_config *ctx, struct cmt *cmt);
/* ! end of v1 HTTP endpoint metrics */

/* General metrics utilities */
bool flb_metrics_is_empty(struct cmt *cmt);

#endif
#endif /* FLB_HAVE_METRICS */
