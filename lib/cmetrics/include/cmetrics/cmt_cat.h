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

#ifndef CMT_CAT_H
#define CMT_CAT_H

#include <cmetrics/cmetrics.h>

struct cmt_counter;
struct cmt_gauge;
struct cmt_untyped;
struct cmt_histogram;
struct cmt_exp_histogram;
struct cmt_summary;

int cmt_cat_copy_label_keys(struct cmt_map *map, char **out);
int cmt_cat_copy_map(struct cmt_opts *opts, struct cmt_map *dst, struct cmt_map *src);
int cmt_cat_counter(struct cmt *cmt, struct cmt_counter *counter, struct cmt_map *filtered_map);
int cmt_cat_gauge(struct cmt *cmt, struct cmt_gauge *gauge, struct cmt_map *filtered_map);
int cmt_cat_untyped(struct cmt *cmt, struct cmt_untyped *untyped, struct cmt_map *filtered_map);
int cmt_cat_histogram(struct cmt *cmt, struct cmt_histogram *histogram, struct cmt_map *filtered_map);
int cmt_cat_exp_histogram(struct cmt *cmt, struct cmt_exp_histogram *exp_histogram, struct cmt_map *filtered_map);
int cmt_cat_summary(struct cmt *cmt, struct cmt_summary *summary, struct cmt_map *filtered_map);
int cmt_cat(struct cmt *dst, struct cmt *src);

#endif
