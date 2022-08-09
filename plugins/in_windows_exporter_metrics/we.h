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

#ifndef FLB_WINDOWS_EXPORTER_H
#define FLB_WINDOWS_EXPORTER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_metrics.h>

#include <monkey/mk_core/mk_list.h>
#include <fluent-bit/flb_sds.h>

#include "we_metric.h"

#define PERFLIB_COUNTER_TYPE_COUNTER          0x400
#define PERFLIB_COUNTER_FLAG_BASE_VALUE       0x00030000
#define PERFLIB_COUNTER_FLAG_BASE_NANOSECONDS 0x00100000

struct we_perflib_counter_definition {
    char          *name_index_str;
    uint32_t       name_index;
    char          *name;
    uint32_t       help_index;
    char          *help;

    uint32_t       type;
    uint32_t       size;
    uint32_t       offset;
    uint32_t       detail_level;

    struct mk_list _head;
};

union we_perflib_value {
    uint64_t as_qword;
    double   as_double;
    uint32_t as_dword;
    float    as_float;
};

struct we_perflib_counter {
    struct we_perflib_instance           *parent;
    struct we_perflib_counter_definition *definition;
    union  we_perflib_value               primary_value;
    union  we_perflib_value               secondary_value;
    struct mk_list                        _head;
};

struct we_perflib_instance {
    char                     *name;
    struct we_perflib_object *parent;
    struct flb_hash_table    *counters;
    struct mk_list            _head;
};

struct we_perflib_object {
    char             *name;
    int64_t           time;
    int64_t           frequency;
    int64_t           hundred_ns_time;
    size_t            counter_count;
    size_t            instance_count;
    struct flb_hash_table *instances;
    struct mk_list    counter_definitions;
};


struct we_perflib_context {
    struct flb_hash_table *counter_indexes;
};

struct we_cpu_counters {
    struct we_perflib_metric_source *metric_sources;
    struct we_perflib_metric_spec   *metric_specs;
    int                              operational;
    struct flb_hash_table           *metrics;
    char                            *query;
};

struct flb_we {
    /* configuration */
    int scrape_interval;

    int coll_fd;                                      /* collector fd     */
    struct cmt *cmt;                                  /* cmetrics context */
    struct flb_input_instance *ins;                   /* input instance   */
    struct mk_list *collectors;

    struct we_perflib_context perflib_context;

    float windows_version;

    /*
     * Metrics Contexts
     * ----------------
     */

    struct we_cpu_counters cpu;

};

typedef int (*collector_cb)(struct flb_we *);

#endif
