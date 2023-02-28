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
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_counter.h>

struct cmt_counter *cmt_counter_create(struct cmt *cmt,
                                       char *ns, char *subsystem,
                                       char *name, char *help,
                                       int label_count, char **label_keys)
{
    int ret;
    struct cmt_counter *counter;

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

    counter = calloc(1, sizeof(struct cmt_counter));
    if (!counter) {
        cmt_errno();
        return NULL;
    }
    cfl_list_add(&counter->_head, &cmt->counters);

    ret = cmt_opts_init(&counter->opts, ns, subsystem, name, help);
    if (ret == -1) {
        cmt_log_error(cmt, "unable to initialize options for counter");
        cmt_counter_destroy(counter);
        return NULL;
    }

    /* Create the map */
    counter->map = cmt_map_create(CMT_COUNTER, &counter->opts, label_count, label_keys,
                                  (void *) counter);
    if (!counter->map) {
        cmt_log_error(cmt, "unable to allocate map for counter");
        cmt_counter_destroy(counter);
        return NULL;
    }
    /* set default counter aggregation type to cumulative */
    counter->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;

    counter->cmt = cmt;
    return counter;
}

void cmt_counter_allow_reset(struct cmt_counter *counter)
{
    counter->allow_reset = 1;
}

int cmt_counter_destroy(struct cmt_counter *counter)
{
    cfl_list_del(&counter->_head);
    cmt_opts_exit(&counter->opts);

    if (counter->map) {
        cmt_map_destroy(counter->map);
    }
    free(counter);
    return 0;
}

int cmt_counter_inc(struct cmt_counter *counter,
                    uint64_t timestamp,
                    int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&counter->opts,
                                counter->map, labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(counter->cmt, "unable to retrieve metric: %s for counter %s_%s_%s",
                      counter->map, counter->opts.ns, counter->opts.subsystem,
                      counter->opts.name);
        return -1;
    }
    cmt_metric_inc(metric, timestamp);
    return 0;
}

int cmt_counter_add(struct cmt_counter *counter, uint64_t timestamp, double val,
                    int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&counter->opts,
                                counter->map, labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(counter->cmt, "unable to retrieve metric: %s for counter %s_%s_%s",
                      counter->map, counter->opts.ns, counter->opts.subsystem,
                      counter->opts.name);
        return -1;
    }
    cmt_metric_add(metric, timestamp, val);
    return 0;
}

/* Set counter value, new value cannot be smaller than current value */
int cmt_counter_set(struct cmt_counter *counter, uint64_t timestamp, double val,
                    int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&counter->opts, counter->map,
                                labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        cmt_log_error(counter->cmt, "unable to retrieve metric: %s for counter %s_%s_%s",
                      counter->map, counter->opts.ns, counter->opts.subsystem,
                      counter->opts.name);
        return -1;
    }

    if (cmt_metric_get_value(metric) > val && counter->allow_reset == 0) {
        cmt_log_error(counter->cmt, "attempting to reset unresetable counter: %s_%s_%s",
                      counter->opts.ns, counter->opts.subsystem,
                      counter->opts.name);
        return -1;
    }
    cmt_metric_set(metric, timestamp, val);
    return 0;
}

int cmt_counter_get_val(struct cmt_counter *counter,
                        int labels_count, char **label_vals, double *out_val)
{
    int ret;
    double val = 0;

    ret = cmt_map_metric_get_val(&counter->opts,
                                 counter->map, labels_count, label_vals,
                                 &val);
    if (ret == -1) {
        cmt_log_error(counter->cmt, "unable to retrieve metric: %s for counter %s_%s_%s",
                      counter->map, counter->opts.ns, counter->opts.subsystem,
                      counter->opts.name);
        return -1;
    }
    *out_val = val;
    return 0;
}
