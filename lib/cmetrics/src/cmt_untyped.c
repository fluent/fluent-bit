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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_untyped.h>

struct cmt_untyped *cmt_untyped_create(struct cmt *cmt,
                                       char *namespace, char *subsystem,
                                       char *name, char *help,
                                       int label_count, char **label_keys)
{
    int ret;
    struct cmt_untyped *untyped;

    if (!name || !help) {
        return NULL;
    }

    if (strlen(name) == 0 || strlen(help) == 0) {
        return NULL;
    }

    untyped = calloc(1, sizeof(struct cmt_untyped));
    if (!untyped) {
        cmt_errno();
        return NULL;
    }
    mk_list_add(&untyped->_head, &cmt->untypeds);

    ret = cmt_opts_init(&untyped->opts, namespace, subsystem, name, help);
    if (ret == -1) {
        cmt_untyped_destroy(untyped);
        return NULL;
    }

    /* Create the map */
    untyped->map = cmt_map_create(CMT_UNTYPED, &untyped->opts, label_count, label_keys);
    if (!untyped->map) {
        cmt_untyped_destroy(untyped);
        return NULL;
    }

    return untyped;
}

int cmt_untyped_destroy(struct cmt_untyped *untyped)
{
    mk_list_del(&untyped->_head);
    cmt_opts_exit(&untyped->opts);

    if (untyped->map) {
        cmt_map_destroy(untyped->map);
    }
    free(untyped);
    return 0;
}

/* Set untyped value, new value cannot be smaller than current value */
int cmt_untyped_set(struct cmt_untyped *untyped, uint64_t timestamp, double val,
                    int labels_count, char **label_vals)
{
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(&untyped->opts, untyped->map,
                                labels_count, label_vals,
                                CMT_TRUE);
    if (!metric) {
        return -1;
    }

    if (cmt_metric_get_value(metric) > val) {
        return -1;
    }
    cmt_metric_set(metric, timestamp, val);
    return 0;
}

int cmt_untyped_get_val(struct cmt_untyped *untyped,
                        int labels_count, char **label_vals, double *out_val)
{
    int ret;
    double val = 0;

    ret = cmt_map_metric_get_val(&untyped->opts,
                                 untyped->map, labels_count, label_vals,
                                 &val);
    if (ret == -1) {
        return -1;
    }
    *out_val = val;
    return 0;
}
