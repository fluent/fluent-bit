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

#ifndef CMT_MAP_H
#define CMT_MAP_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_opts.h>
#include <cmetrics/cmt_metric.h>

struct cmt_map_label {
    cfl_sds_t name;             /* Label key name */
    struct cfl_list _head;       /* Link to list cmt_labels_map->labels */
};

struct cmt_map {
    int type;                   /* Metric type */
    struct cmt_opts *opts;      /* Reference to parent 'opts' */
    cfl_sds_t unit;             /* Metric unit */

    /* A map without label keys, uses direct access to the static metric ctx */
    int metric_static_set;      /* is the static metric set ? */
    struct cmt_metric metric;

    /* Used when labels are set */
    struct cfl_list metrics;     /* List of metrics */
    int label_count;            /* Number of labels */
    struct cfl_list label_keys;  /* Linked list of labels */
    void *parent;
};

struct cmt_map *cmt_map_create(int type, struct cmt_opts *opts,
                               int count, char **labels, void *parent);
void cmt_map_destroy(struct cmt_map *map);

struct cmt_metric *cmt_map_metric_get(struct cmt_opts *opts, struct cmt_map *map,
                                      int labels_count, char **labels_val,
                                      int write_op);
int cmt_map_metric_get_val(struct cmt_opts *opts, struct cmt_map *map,
                           int labels_count, char **labels_val,
                           double *out_val);

void destroy_label_list(struct cfl_list *label_list);

#endif
