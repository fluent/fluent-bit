/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2024 The CMetrics Authors
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

#ifndef CMT_FILTER_H
#define CMT_FILTER_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_cat.h>

#define CMT_FILTER_EXCLUDE             (1 << 1)
#define CMT_FILTER_PREFIX              (1 << 2)
#define CMT_FILTER_SUBSTRING           (1 << 3)
#define CMT_FILTER_REGEX_SEARCH_LABELS (1 << 4)

#define CMT_FILTER_SUCCESS           0
#define CMT_FILTER_INVALID_ARGUMENT -1
#define CMT_FILTER_INVALID_FLAGS    -2
#define CMT_FILTER_FAILED_OPERATION -3

int cmt_filter(struct cmt *dst, struct cmt *src,
               const char *fqname, const char *label_key,
               void *compare_ctx, int (*compare)(void *compare_ctx, const char *str, size_t slen),
               int flags);

int cmt_filter_with_label_pair(struct cmt *dst, struct cmt *src,
                               const char *label_key,
                               const char *label_value);

#endif
