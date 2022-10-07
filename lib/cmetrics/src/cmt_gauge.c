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
#include <cmetrics/cmt_math.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_gauge.h>

struct cmt_gauge *cmt_gauge_create(struct cmt *cmt,
                                   char *ns, char *subsystem, char *name,
                                   char *help, int label_count, char **label_keys)
{
    int ret;
    struct cmt_gauge *gauge;

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

    gauge = calloc(1, sizeof(struct cmt_gauge));
    if (!gauge) {
        cmt_errno();
        return NULL;
    }
    cfl_list_add(&gauge->_head, &cmt->gauges);

    /* Initialize options */
    ret = cmt_opts_init(&gauge->opts, ns, subsystem, name, help);
    if (ret == -1) {
        cmt_log_error(cmt, "unable to initialize options for gauge");
        cmt_gauge_destroy(gauge);
        return NULL;
    }

    /* Create the map */
    gauge->map = cmt_map_create(CMT_GAUGE, &gauge->opts, label_count, label_keys,
                                (void *) gauge);
    if (!gauge->map) {
        cmt_log_error(cmt, "unable to allocate map for gauge");
        cmt_gauge_destroy(gauge);
        return NULL;
    }

    gauge->cmt = cmt;

    return gauge;
}

int cmt_gauge_destroy(struct cmt_gauge *gauge)
{
    cfl_list_del(&gauge->_head);
    cmt_opts_exit(&gauge->opts);
    if (gauge->map) {
        cmt_map_destroy(gauge->map);
    }
    free(gauge);
    return 0;
}

int cmt_gauge_set(struct cmt_gauge *gauge, uint64_t timestamp, double val,
                  int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&gauge->opts, gauge->map, labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(gauge->cmt, "unable to retrieve metric: %s for gauge %s_%s_%s",
                      gauge->map, gauge->opts.ns, gauge->opts.subsystem,
                      gauge->opts.name);
        return -1;
    }
    cmt_metric_set(metric, timestamp, val);
    return 0;
}

int cmt_gauge_inc(struct cmt_gauge *gauge, uint64_t timestamp,
                  int labels_count, char **label_vals)

{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&gauge->opts, gauge->map, labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(gauge->cmt, "unable to retrieve metric: %s for gauge %s_%s_%s",
                      gauge->map, gauge->opts.ns, gauge->opts.subsystem,
                      gauge->opts.name);
        return -1;
    }
    cmt_metric_inc(metric, timestamp);
    return 0;
}

int cmt_gauge_dec(struct cmt_gauge *gauge, uint64_t timestamp,
                  int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&gauge->opts, gauge->map, labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(gauge->cmt, "unable to retrieve metric: %s for gauge %s_%s_%s",
                      gauge->map, gauge->opts.ns, gauge->opts.subsystem,
                      gauge->opts.name);
        return -1;
    }
    cmt_metric_dec(metric, timestamp);
    return 0;
}

int cmt_gauge_add(struct cmt_gauge *gauge, uint64_t timestamp, double val,
                  int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&gauge->opts, gauge->map, labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(gauge->cmt, "unable to retrieve metric: %s for gauge %s_%s_%s",
                      gauge->map, gauge->opts.ns, gauge->opts.subsystem,
                      gauge->opts.name);
        return -1;
    }
    cmt_metric_add(metric, timestamp, val);
    return 0;
}

int cmt_gauge_sub(struct cmt_gauge *gauge, uint64_t timestamp, double val,
                  int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&gauge->opts, gauge->map, labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(gauge->cmt, "unable to retrieve metric: %s for gauge %s_%s_%s",
                      gauge->map, gauge->opts.ns, gauge->opts.subsystem,
                      gauge->opts.name);
        return -1;
    }
    cmt_metric_sub(metric, timestamp, val);
    return 0;
}

int cmt_gauge_get_val(struct cmt_gauge *gauge,
                      int labels_count, char **label_vals, double *out_val)
{
    int ret;
    double val = 0;

    ret = cmt_map_metric_get_val(&gauge->opts,
                                 gauge->map, labels_count, label_vals,
                                 &val);
    if (ret == -1) {
        cmt_log_error(gauge->cmt,
                      "unable to retrieve metric value: %s for gauge %s_%s_%s",
                      gauge->map, gauge->opts.ns, gauge->opts.subsystem,
                      gauge->opts.name);
        return -1;
    }
    *out_val = val;
    return 0;
}
