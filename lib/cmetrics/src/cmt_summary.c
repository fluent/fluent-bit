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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_math.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_summary.h>

#include <stdarg.h>

/*
 * CMetrics 'Summary' metric type is only a container for values reported by a
 * scrapper. We don't do data observation or calculate values for quantiles, we
 * just compose a structure to keep the reported values.
 *
 * This metric type uses very similar 'Histogram' structures and interfaces.
 */

struct cmt_summary *cmt_summary_create(struct cmt *cmt,
                                       char *ns, char *subsystem,
                                       char *name, char *help,
                                       size_t quantiles_count,
                                       double *quantiles,
                                       int label_count, char **label_keys)
{
    int i;
    int ret;
    struct cmt_summary *s;

    if (!ns) {
        cmt_log_error(cmt, "null ns not allowed");
        return NULL;
    }

    if (!subsystem) {
        cmt_log_error(cmt, "null subsystem not allowed");
        return NULL;
    }

    if (!name || strlen(name) == 0) {
        cmt_log_error(cmt, "undefined name");
        return NULL;
    }

    if (!help || strlen(help) == 0) {
        cmt_log_error(cmt, "undefined help");
        return NULL;
    }

    s = calloc(1, sizeof(struct cmt_summary));
    if (!s) {
        cmt_errno();
        return NULL;
    }
    cfl_list_add(&s->_head, &cmt->summaries);

    /* initialize options */
    ret = cmt_opts_init(&s->opts, ns, subsystem, name, help);
    if (ret == -1) {
        cmt_log_error(cmt, "unable to initialize options for summary");
        cmt_summary_destroy(s);
        return NULL;
    }

    /* Create the map */
    s->map = cmt_map_create(CMT_SUMMARY, &s->opts, label_count, label_keys,
                            (void *) s);
    if (!s->map) {
        cmt_log_error(cmt, "unable to allocate map for summary");
        cmt_summary_destroy(s);
        return NULL;
    }

    /* create quantiles buffer */
    if (quantiles_count > 0) {
        s->quantiles_count = quantiles_count;
        s->quantiles = calloc(1, sizeof(double) * quantiles_count);
        if (!s->quantiles_count) {
            cmt_errno();
            cmt_summary_destroy(s);
            return NULL;
        }

        /* set quantile */
        for (i = 0; i < quantiles_count; i++) {
            s->quantiles[i] = quantiles[i];
        }
    }

    return s;
}

int cmt_summary_destroy(struct cmt_summary *summary)
{
    cfl_list_del(&summary->_head);
    cmt_opts_exit(&summary->opts);

    if (summary->map) {
        cmt_map_destroy(summary->map);
    }

    if (summary->quantiles) {
        free(summary->quantiles);
    }

    free(summary);
    return 0;
}

double cmt_summary_quantile_get_value(struct cmt_metric *metric, int quantile_id)
{
    uint64_t val;

    if (quantile_id < 0 /*|| quantile_id > metric->sum_quantiles_count*/) {
        return 0;
    }

    val = cmt_atomic_load(&metric->sum_quantiles[quantile_id]);
    return cmt_math_uint64_to_d64(val);
}

double cmt_summary_get_sum_value(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->sum_sum);
    return cmt_math_uint64_to_d64(val);
}

uint64_t cmt_summary_get_count_value(struct cmt_metric *metric)
{
    uint64_t val;

    val = cmt_atomic_load(&metric->sum_count);
    return val;
}

static inline int summary_quantile_exchange(struct cmt_metric *metric,
                                            uint64_t timestamp,
                                            int quantile_id,
                                            double new_value, double old_value)
{
    uint64_t tmp_new;
    uint64_t tmp_old;
    int      result;

    tmp_new = cmt_math_d64_to_uint64(new_value);
    tmp_old = cmt_math_d64_to_uint64(old_value);

    result = cmt_atomic_compare_exchange(&metric->sum_quantiles[quantile_id],
                                         tmp_old, tmp_new);

    if (result == 0) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);
    return 1;
}

static inline int summary_sum_exchange(struct cmt_metric *metric,
                                       uint64_t timestamp,
                                       double new_value, double old_value)
{
    uint64_t tmp_new;
    uint64_t tmp_old;
    int      result;

    tmp_new = cmt_math_d64_to_uint64(new_value);
    tmp_old = cmt_math_d64_to_uint64(old_value);

    result = cmt_atomic_compare_exchange(&metric->sum_sum, tmp_old, tmp_new);

    if (result == 0) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);
    return 1;
}

static inline int summary_count_exchange(struct cmt_metric *metric,
                                         uint64_t timestamp,
                                         uint64_t new, uint64_t old)
{
    int result;

    result = cmt_atomic_compare_exchange(&metric->sum_count, old, new);
    if (result == 0) {
        return 0;
    }

    cmt_atomic_store(&metric->timestamp, timestamp);
    return 1;
}

void cmt_summary_quantile_set(struct cmt_metric *metric, uint64_t timestamp,
                              int quantile_id, double val)
{
    double   old;
    double   new;
    int      result;

    do {
        old = cmt_summary_quantile_get_value(metric, quantile_id);
        new = val;
        result = summary_quantile_exchange(metric, timestamp, quantile_id, new, old);
    }
    while (0 == result);
}

void cmt_summary_sum_set(struct cmt_metric *metric, uint64_t timestamp, double val)
{
    double   old;
    double   new;
    int      result;

    do {
        old = cmt_summary_get_sum_value(metric);
        new = val;
        result = summary_sum_exchange(metric, timestamp, new, old);
    }
    while (0 == result);
}

void cmt_summary_count_set(struct cmt_metric *metric, uint64_t timestamp,
                           uint64_t count)
{
    int result;
    uint64_t old;
    uint64_t new;

    do {
        old = cmt_atomic_load(&metric->sum_count);
        new = count;

        result = summary_count_exchange(metric, timestamp, new, old);
    }
    while (result == 0);
}

int cmt_summary_set_default(struct cmt_summary *summary,
                            uint64_t timestamp,
                            double *quantile_values,
                            double sum,
                            uint64_t count,
                            int labels_count, char **label_vars)
{
    int i;
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&summary->opts, summary->map,
                                labels_count, label_vars,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(summary->cmt, "unable to retrieve metric for summary %s_%s_%s",
                      summary->opts.ns, summary->opts.subsystem,
                      summary->opts.name);
        return -1;
    }


    if (!metric->sum_quantiles && summary->quantiles_count) {
        metric->sum_quantiles = calloc(1, sizeof(uint64_t) * summary->quantiles_count);
        if (!metric->sum_quantiles) {
            cmt_errno();
            return -1;
        }
        metric->sum_quantiles_count = summary->quantiles_count;
    }

    /* set quantile values */
    if (quantile_values) {
        /* yes, quantile values are set */
        cmt_atomic_store(&metric->sum_quantiles_set, CMT_TRUE);

        /* populate each quantile */
        for (i = 0; i < summary->quantiles_count; i++) {
            cmt_summary_quantile_set(metric, timestamp, i, quantile_values[i]);
        }
    }

    cmt_summary_sum_set(metric, timestamp, sum);
    cmt_summary_count_set(metric, timestamp, count);

    return 0;
}