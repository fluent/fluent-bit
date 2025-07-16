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
    size_t            total_byte_length;
    size_t            definition_length;
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

struct we_cache_counters {
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

struct we_wmi_service_counters {
    struct wmi_query_spec *info;
    struct cmt_gauge *information;
    struct cmt_gauge *state;
    struct cmt_gauge *start_mode;
    struct cmt_gauge *status;
    int operational;
};

struct we_wmi_memory_counters {
    struct wmi_query_spec *info;
    struct cmt_gauge      *available_bytes;
    struct cmt_gauge      *cache_bytes;
    struct cmt_gauge      *cache_bytes_peak;
    struct cmt_gauge      *cache_faults_total;
    struct cmt_gauge      *commit_limit;
    struct cmt_gauge      *committed_bytes;
    struct cmt_gauge      *demand_zero_faults_total;
    struct cmt_gauge      *free_and_zero_page_list_bytes;
    struct cmt_gauge      *free_system_page_table_entries;
    struct cmt_gauge      *modified_page_list_bytes;
    struct cmt_gauge      *page_faults_total;
    struct cmt_gauge      *swap_page_reads_total;
    struct cmt_gauge      *swap_pages_read_total;
    struct cmt_gauge      *swap_pages_written_total;
    struct cmt_gauge      *swap_page_operations_total;
    struct cmt_gauge      *swap_page_writes_total;
    struct cmt_gauge      *pool_nonpaged_allocs_total;
    struct cmt_gauge      *pool_nonpaged_bytes;
    struct cmt_gauge      *pool_paged_allocs_total;
    struct cmt_gauge      *pool_paged_bytes;
    struct cmt_gauge      *pool_paged_resident_bytes;
    struct cmt_gauge      *standby_cache_core_bytes;
    struct cmt_gauge      *standby_cache_normal_priority_bytes;
    struct cmt_gauge      *standby_cache_reserve_bytes;
    struct cmt_gauge      *system_cache_resident_bytes;
    struct cmt_gauge      *system_code_resident_bytes;
    struct cmt_gauge      *system_code_total_bytes;
    struct cmt_gauge      *system_driver_resident_bytes;
    struct cmt_gauge      *system_driver_total_bytes;
    struct cmt_gauge      *transition_faults_total;
    struct cmt_gauge      *transition_pages_repurposed_total;
    struct cmt_gauge      *write_copies_total;
    int                    operational;
};

struct we_wmi_paging_file_counters {
    struct wmi_query_spec *info;
    struct cmt_gauge      *allocated_base_size_megabytes;
    struct cmt_gauge      *current_usage_megabytes;
    struct cmt_gauge      *peak_usage_megabytes;
    int                    operational;
};

struct we_wmi_process_counters {
    struct wmi_query_spec *info;
    struct cmt_gauge      *start_time;
    struct cmt_gauge      *handles;
    struct cmt_gauge      *cpu_time_total;
    struct cmt_gauge      *io_bytes_total;
    struct cmt_gauge      *io_operations_total;
    struct cmt_gauge      *page_faults_total;
    struct cmt_gauge      *page_file_bytes;
    struct cmt_gauge      *pool_bytes;
    struct cmt_gauge      *priority_base;
    struct cmt_gauge      *thread_count;
    struct cmt_gauge      *private_bytes;
    struct cmt_gauge      *virtual_bytes;
    struct cmt_gauge      *working_set_private_bytes;
    struct cmt_gauge      *working_set_peak_bytes;
    struct cmt_gauge      *working_set_bytes;
    int                    operational;
};

struct we_wmi_tcp_counters {
    int                          operational;
    struct wmi_query_spec       *v4_info;
    struct wmi_query_spec       *v6_info;
    
    struct cmt_counter          *connection_failures;
    struct cmt_gauge            *connections_active;
    struct cmt_counter          *connections_established;
    struct cmt_counter          *connections_passive;
    struct cmt_counter          *connections_reset;
    struct cmt_gauge            *segments_per_sec;
    struct cmt_gauge            *segments_received_per_sec;
    struct cmt_gauge            *segments_retransmitted_per_sec;
    struct cmt_gauge            *segments_sent_per_sec;
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
    char *raw_where_clause;
    char *raw_service_include;
    char *raw_service_exclude;
    char *raw_allowing_process;
    char *raw_denying_process;
    char *service_include_buffer;
    int   service_include_buffer_size;
    char *service_exclude_buffer;
    int   service_exclude_buffer_size;

    struct flb_regex *allowing_disk_regex;
    struct flb_regex *denying_disk_regex;
    struct flb_regex *allowing_nic_regex;
    struct flb_regex *allowing_process_regex;
    struct flb_regex *denying_process_regex;

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
    int cache_scrape_interval;
    int wmi_thermalzone_scrape_interval;
    int wmi_cpu_info_scrape_interval;
    int wmi_logon_scrape_interval;
    int wmi_system_scrape_interval;
    int wmi_service_scrape_interval;
    int wmi_memory_scrape_interval;
    int wmi_paging_file_scrape_interval;
    int wmi_process_scrape_interval;
    int wmi_tcp_scrape_interval;

    int coll_cpu_fd;                                    /* collector fd (cpu)    */
    int coll_net_fd;                                    /* collector fd (net)  */
    int coll_logical_disk_fd;                           /* collector fd (logical_disk) */
    int coll_cs_fd;                                     /* collector fd (cs) */
    int coll_os_fd;                                     /* collector fd (os)    */
    int coll_cache_fd;                                  /* collector fd (cache)    */
    int coll_wmi_thermalzone_fd;                        /* collector fd (wmi_thermalzone) */
    int coll_wmi_cpu_info_fd;                           /* collector fd (wmi_cpu_info) */
    int coll_wmi_logon_fd;                              /* collector fd (wmi_logon)    */
    int coll_wmi_system_fd;                             /* collector fd (wmi_system)    */
    int coll_wmi_service_fd;                            /* collector fd (wmi_service) */
    int coll_wmi_memory_fd;                             /* collector fd (wmi_memory)    */
    int coll_wmi_paging_file_fd;                        /* collector fd (wmi_paging_file) */
    int coll_wmi_process_fd;                            /* collector fd (wmi_process) */
    int coll_wmi_tcp_fd;                                /* collector fd (wmi_tcp) */

    /*
     * Metrics Contexts
     * ----------------
     */

    struct we_cpu_counters cpu;
    struct we_net_counters net;
    struct we_logical_disk_counters logical_disk;
    struct we_cs_counters cs;
    struct we_os_counters *os;
    struct we_cache_counters cache;
    struct we_wmi_thermal_counters *wmi_thermals;
    struct we_wmi_cpu_info_counters *wmi_cpu_info;
    struct we_wmi_logon_counters *wmi_logon;
    struct we_wmi_system_counters *wmi_system;
    struct we_wmi_service_counters *wmi_service;
    struct we_wmi_memory_counters *wmi_memory;
    struct we_wmi_paging_file_counters *wmi_paging_file;
    struct we_wmi_process_counters *wmi_process;
    struct we_wmi_tcp_counters *wmi_tcp;
};

typedef int (*collector_cb)(struct flb_we *);

#endif
