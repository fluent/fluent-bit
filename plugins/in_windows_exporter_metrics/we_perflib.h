/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_WE_PERFLIB_H
#define FLB_WE_PERFLIB_H

#include "we.h"
#include "we_metric.h"

#define WE_PERFLIB_REGISTRY_PATH                 \
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib"

#define WE_PERFLIB_STRING_COUNT_KEY              "Last Help"
#define WE_PERFLIB_COUNTER_KEY_NAME              "Counter 009"

#define WE_PERFLIB_METRIC_LABEL_LIST_SIZE        64

#define WE_PERFLIB_QUERY_BUFFER_INITIAL_SIZE     (32 * 1024)
#define WE_PERFLIB_QUERY_BUFFER_INCREMENT_SIZE   (16 * 1024)

#define WE_PERFLIB_WINDOWS_EPOCH                 ((double) 1 / 1e7)
#define WE_PERFLIB_TICKS_TO_SECONDS_SCALE_FACTOR ((double) 116444736000000000)

typedef int (*we_perflib_instance_filter)(char *, struct flb_we *);
typedef int (*we_perflib_label_prepend_hook)(char **,
                                             size_t,
                                             size_t *,
                                             struct we_perflib_metric_source *,
                                             char *,
                                             struct we_perflib_counter *);

int we_perflib_init(struct flb_we *ctx);
int we_perflib_exit(struct flb_we *ctx);

int we_perflib_query(struct flb_we *ctx,
                     char *counter_name,
                     struct we_perflib_object **out_object);

struct we_perflib_counter *we_perflib_get_counter(struct we_perflib_object *object,
                                                  char *instance_name,
                                                  char *counter_name);

void we_perflib_destroy_object(struct we_perflib_object *object);

char *we_perflib_get_counter_type_as_text(uint32_t counter_Type);

int we_perflib_update_counters(struct flb_we                   *ctx,
                               char                            *query,
                               struct we_perflib_metric_source *metric_sources,
                               we_perflib_instance_filter       filter_hook,
                               we_perflib_label_prepend_hook    label_prepend_hook);

double we_perflib_get_adjusted_counter_value(struct we_perflib_counter *counter);

#endif