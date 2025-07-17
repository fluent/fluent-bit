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

#ifndef FLB_METRIC_H
#define FLB_METRIC_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_metrics.h>

struct we_perflib_metric_spec {
    int      type;
    char    *name;
    char    *description;
    char    *raw_label_set;
    char   **label_set;
    size_t   label_set_size;
    void    *metric_instance;
};

struct we_perflib_metric_source {
    struct we_perflib_metric_spec *parent;
    char                          *parent_name;
    char                          *name;
    char                          *raw_label_set;
    char                         **label_set;
    size_t                         label_set_size;
    int                            use_secondary_value;
};

#define WE_PERFLIB_SPEC(type_, name_, description_, raw_label_set_) \
        { \
            .type = type_, \
            .name = name_, \
            .description = description_, \
            .raw_label_set = raw_label_set_, \
            .label_set = NULL, \
            .label_set_size = 0, \
            .metric_instance = NULL \
        }

#define WE_PERFLIB_COUNTER_SPEC(name_, description_, raw_label_set_) \
        WE_PERFLIB_SPEC(CMT_COUNTER, name_, description_, raw_label_set_)

#define WE_PERFLIB_GAUGE_SPEC(name_, description_, raw_label_set_) \
        WE_PERFLIB_SPEC(CMT_GAUGE, name_, description_, raw_label_set_)

#define WE_PERFLIB_TERMINATOR_SPEC() \
        WE_PERFLIB_SPEC(0, NULL, NULL, NULL)

#define WE_PERFLIB_METRIC_SOURCE(parent_name_, name_, raw_label_set_) \
        { \
            .parent = NULL, \
            .parent_name = parent_name_, \
            .name = name_, \
            .raw_label_set = raw_label_set_, \
            .label_set = NULL, \
            .label_set_size = 0 \
        }

#define WE_PERFLIB_TERMINATOR_SOURCE() \
    WE_PERFLIB_METRIC_SOURCE(NULL, NULL, NULL)


void we_deinitialize_perflib_metric_sources(struct we_perflib_metric_source *sources);
int we_initialize_perflib_metric_sources(
    struct flb_hash                  *lookup_table,
    struct we_perflib_metric_source **out_sources,
    struct we_perflib_metric_source  *in_sources);


void we_deinitialize_perflib_metric_specs(struct we_perflib_metric_spec *specs);
int we_initialize_perflib_metric_specs(
    struct cmt                     *context,
    struct flb_hash                *lookup_table,
    char                           *namespace,
    char                           *subsystem,
    struct we_perflib_metric_spec **out_specs,
    struct we_perflib_metric_spec  *in_specs);

#endif
