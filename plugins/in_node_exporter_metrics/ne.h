/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_NODE_EXPORTER_H
#define FLB_NODE_EXPORTER_H

/* utils: scan content type expected */
#define NE_SCAN_FILE      1
#define NE_SCAN_DIR       2

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_metrics.h>

struct flb_ne {
    /* configuration */
    flb_sds_t path_procfs;
    flb_sds_t path_sysfs;
    int scrape_interval;

    int coll_fd;                                      /* collector fd     */
    struct cmt *cmt;                                  /* cmetrics context */
    struct flb_input_instance *ins;                   /* input instance   */

    /*
     * Metrics Contexts
     * ----------------
     */

    /* cpu_linux */
    struct cmt_counter *cpu_core_throttles;
    struct cmt_counter *cpu_package_throttles;

    /* cpufreq_linux */
    struct cmt_gauge *cpu_freq_hertz;
    struct cmt_gauge *cpu_freq_min_hertz;
    struct cmt_gauge *cpu_freq_max_hertz;

    /* cpufreq scaling linux */
    struct cmt_gauge *cpu_scaling_freq_hertz;
    struct cmt_gauge *cpu_scaling_freq_max_hertz;
    struct cmt_gauge *cpu_scaling_freq_min_hertz;

    /* cpu seconds & guest seconds */
    struct cmt_counter *cpu_seconds;
    struct cmt_counter *cpu_guest_seconds;

    /* meminfo hash table */
    struct flb_hash_table *meminfo_ht;

    /* diskstats: abbreviation 'dt' */
    void *dt_metrics;
    struct flb_regex *dt_regex_skip_devices;

    /* uname */
    struct cmt_gauge *uname;

    /* stat_linux */
    struct cmt_counter *st_intr;
    struct cmt_counter *st_context_switches;
    struct cmt_gauge   *st_boot_time;
    struct cmt_counter *st_forks;
    struct cmt_gauge   *st_procs_running;
    struct cmt_gauge   *st_procs_blocked;

    /* vmstat_linux */
    struct flb_hash_table *vml_ht;
    struct flb_regex *vml_regex_fields;

    /* netdev */
    struct flb_hash_table *netdev_ht;

    /* time */
    struct cmt_gauge *time;

    /* loadavg */
    struct cmt_gauge *lavg_1;
    struct cmt_gauge *lavg_5;
    struct cmt_gauge *lavg_15;

    /* filefd_linux */
    struct cmt_gauge *filefd_allocated;
    struct cmt_gauge *filefd_maximum;

    /* filesystem: abbreviation 'fs' */
    struct flb_regex *fs_regex_skip_mount;
    struct flb_regex *fs_regex_skip_fs_types;
};

#endif
