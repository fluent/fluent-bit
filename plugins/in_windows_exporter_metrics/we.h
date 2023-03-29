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

#include <windows.h>
#include <wbemidl.h>

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

struct we_net_counters {
    struct we_perflib_metric_source *metric_sources;
    struct we_perflib_metric_spec   *metric_specs;
    int                              operational;
    struct flb_hash_table           *metrics;
    char                            *query;
};

struct we_logical_disk_counters {
    struct we_perflib_metric_source *metric_sources;
    struct we_perflib_metric_spec   *metric_specs;
    int                              operational;
    struct flb_hash_table           *metrics;
    char                            *query;
};

struct wmi_query_spec;

struct we_wmi_thermal_counters {
    struct wmi_query_spec *temperature_celsius;
    struct wmi_query_spec *percent_passive_limit;
    struct wmi_query_spec *throttle_reasons;
    int                    operational;
};

struct we_wmi_cpu_info_counters {
    struct wmi_query_spec *info;
    int                    operational;
};

struct we_wmi_logon_counters {
    struct wmi_query_spec *info;
    int                    operational;
};

struct we_wmi_system_counters {
    struct wmi_query_spec *info;
    struct cmt_gauge      *context_switches;
    struct cmt_gauge      *exception_dispatches;
    struct cmt_gauge      *processor_queue;
    struct cmt_gauge      *system_calls;
    struct cmt_gauge      *system_up_time;
    struct cmt_gauge      *threads;
    int                    operational;
};

struct we_os_counters {
    struct cmt_gauge *info;
    struct cmt_gauge *users;
    struct cmt_gauge *physical_memory_free_bytes;
    struct cmt_gauge *time;
    struct cmt_gauge *tz;
    struct cmt_gauge *virtual_memory_free_bytes;
    struct cmt_gauge *processes_limit;
    struct cmt_gauge *process_memory_limit_bytes;
    struct cmt_gauge *processes;
    struct cmt_gauge *virtual_memory_bytes;
    struct cmt_gauge *visible_memory_bytes;
    int operational;
};

struct we_cs_counters {
    struct cmt_gauge *logical_processors;
    struct cmt_gauge *physical_memory_bytes;
    struct cmt_gauge *hostname;
    int operational;
};

struct flb_we {
    /* configuration */
    int scrape_interval;

    int coll_fd;                                      /* collector fd     */
    struct cmt *cmt;                                  /* cmetrics context */
    struct flb_input_instance *ins;                   /* input instance   */
    struct mk_list *collectors;
    char *raw_allowing_disk;
    char *raw_denying_disk;
    char *raw_allowing_nic;

    struct flb_regex *allowing_disk_regex;
    struct flb_regex *denying_disk_regex;
    struct flb_regex *allowing_nic_regex;

    struct we_perflib_context perflib_context;
    /* WMI locator and service contexts */
    IWbemLocator *locator;
    IWbemServices *service;

    float windows_version;

    struct flb_callback *callback;                    /* metric callback */
    struct mk_list *metrics;                          /* enabled metrics */

    /* Individual intervals for metrics */
    int cpu_scrape_interval;
    int net_scrape_interval;
    int logical_disk_scrape_interval;
    int cs_scrape_interval;
    int os_scrape_interval;
    int wmi_thermalzone_scrape_interval;
    int wmi_cpu_info_scrape_interval;
    int wmi_logon_scrape_interval;
    int wmi_system_scrape_interval;

    int coll_cpu_fd;                                    /* collector fd (cpu)    */
    int coll_net_fd;                                    /* collector fd (net)  */
    int coll_logical_disk_fd;                           /* collector fd (logical_disk) */
    int coll_cs_fd;                                     /* collector fd (cs) */
    int coll_os_fd;                                     /* collector fd (os)    */
    int coll_wmi_thermalzone_fd;                        /* collector fd (wmi_thermalzone) */
    int coll_wmi_cpu_info_fd;                           /* collector fd (wmi_cpu_info) */
    int coll_wmi_logon_fd;                              /* collector fd (wmi_logon)    */
    int coll_wmi_system_fd;                             /* collector fd (wmi_system)    */

    /*
     * Metrics Contexts
     * ----------------
     */

    struct we_cpu_counters cpu;
    struct we_net_counters net;
    struct we_logical_disk_counters logical_disk;
    struct we_cs_counters cs;
    struct we_os_counters *os;
    struct we_wmi_thermal_counters *wmi_thermals;
    struct we_wmi_cpu_info_counters *wmi_cpu_info;
    struct we_wmi_logon_counters *wmi_logon;
    struct we_wmi_system_counters *wmi_system;

};

typedef int (*collector_cb)(struct flb_we *);

#endif
