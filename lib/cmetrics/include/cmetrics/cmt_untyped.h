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

#ifndef CMT_UNTYPED_H
#define CMT_UNTYPED_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_opts.h>

struct cmt_untyped {
    struct cmt_opts opts;
    struct cmt_map *map;
    struct cmt *cmt;
    struct cfl_list _head;
};

struct cmt_untyped *cmt_untyped_create(struct cmt *cmt,
                                       char *ns, char *subsystem,
                                       char *name, char *help,
                                       int label_count, char **label_keys);

int cmt_untyped_destroy(struct cmt_untyped *counter);

int cmt_untyped_set(struct cmt_untyped *counter, uint64_t timestamp, double val,
                    int labels_count, char **label_vals);

int cmt_untyped_get_val(struct cmt_untyped *counter,
                        int labels_count, char **label_vals, double *out_val);

#endif
