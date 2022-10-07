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

#ifndef CMT_LABEL_H
#define CMT_LABEL_H

#include <cmetrics/cmetrics.h>

struct cmt_label {
    cfl_sds_t key;             /* Label key */
    cfl_sds_t val;             /* Label value */
    struct cfl_list _head;      /* Link to list cmt_labels->list */
};

struct cmt_labels {
    struct cfl_list list;
};

struct cmt_labels *cmt_labels_create();
void cmt_labels_destroy(struct cmt_labels *labels);
int cmt_labels_add_kv(struct cmt_labels *labels, char *key, char *val);
int cmt_labels_count(struct cmt_labels *labels);

#endif
