/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023-2026 The Fluent Bit Authors
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

#ifndef FLB_PROCESS_EXPORTER_H
#define FLB_PROCESS_EXPORTER_H

/* utils: scan content type expected */
#define NE_SCAN_FILE      1
#define NE_SCAN_DIR       2

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_metrics.h>

#define PE_DEFAULT_ENABLED_METRICS "cpu,io,memory,state,context_switches,fd,start_time,thread_wchan,thread"

#define METRIC_CPU          (1 << 0)
#define METRIC_IO           (1 << 1)
#define METRIC_MEMORY       (1 << 2)
#define METRIC_STATE        (1 << 3)
#define METRIC_CTXT         (1 << 4)
#define METRIC_FD           (1 << 5)
#define METRIC_START_TIME   (1 << 6)
#define METRIC_THREAD_WCHAN (1 << 7)
#define METRIC_THREAD       (1 << 8)

struct flb_pe {
    /* configuration */
    flb_sds_t path_procfs;
    int scrape_interval;

    int coll_fd;                    /* collector fd     */
    struct cmt *cmt;                /* cmetrics context */
    struct flb_input_instance *ins; /* input instance   */
    struct mk_list *metrics;        /* enabled metrics */
    int enabled_flag;               /* indicate enabled metrics */

    /*
     * Metrics Contexts
     * ----------------
     */

    /* process */
    struct cmt_gauge *memory_bytes;
    struct cmt_gauge *start_time;
    struct cmt_gauge *open_fds;
    struct cmt_gauge *fd_ratio;
    struct cmt_counter *cpu_seconds;
    struct cmt_counter *read_bytes;
    struct cmt_counter *write_bytes;
    struct cmt_counter *major_page_faults;
    struct cmt_counter *minor_page_faults;
    struct cmt_counter *context_switches;
    struct cmt_gauge *num_threads;
    struct cmt_gauge *states;

    /* thread */
    struct cmt_gauge *thread_wchan;
    struct cmt_counter *thread_cpu_seconds;
    struct cmt_counter *thread_io_bytes;
    struct cmt_counter *thread_major_page_faults;
    struct cmt_counter *thread_minor_page_faults;
    struct cmt_counter *thread_context_switches;

    flb_sds_t           process_regex_include_list_text;
    flb_sds_t           process_regex_exclude_list_text;
    struct flb_regex   *process_regex_include_list;
    struct flb_regex   *process_regex_exclude_list;
};

#endif
