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
    flb_sds_t path_textfile;
    int scrape_interval;

    int coll_fd;                                      /* collector fd     */
    struct cmt *cmt;                                  /* cmetrics context */
    struct flb_input_instance *ins;                   /* input instance   */
    struct flb_callback *callback;                    /* metric callback */
    struct mk_list *metrics;                          /* enabled metrics */

    /* Individual intervals for metrics */
    int cpu_scrape_interval;
    int cpufreq_scrape_interval;
    int meminfo_scrape_interval;
    int diskstats_scrape_interval;
    int filesystem_scrape_interval;
    int uname_scrape_interval;
    int stat_scrape_interval;
    int time_scrape_interval;
    int loadavg_scrape_interval;
    int vmstat_scrape_interval;
    int netdev_scrape_interval;
    int filefd_scrape_interval;
    int textfile_scrape_interval;

    int coll_cpu_fd;                                    /* collector fd (cpu)    */
    int coll_cpufreq_fd;                                /* collector fd (cpufreq)  */
    int coll_meminfo_fd;                                /* collector fd (meminfo)  */
    int coll_diskstats_fd;                              /* collector fd (diskstat) */
    int coll_filesystem_fd;                             /* collector fd (filesystem) */
    int coll_uname_fd;                                  /* collector fd (uname)    */
    int coll_stat_fd;                                   /* collector fd (stat)    */
    int coll_time_fd;                                   /* collector fd (time)    */
    int coll_loadavg_fd;                                /* collector fd (loadavg)    */
    int coll_vmstat_fd;                                 /* collector fd (vmstat)    */
    int coll_netdev_fd;                                 /* collector fd (netdev)    */
    int coll_filefd_fd;                                 /* collector fd (filefd)    */
    int coll_textfile_fd;                               /* collector fd (textfile)  */

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
    struct cmt_gauge *fs_avail_bytes;
    struct cmt_gauge *fs_device_error;
    struct cmt_gauge *fs_files;
    struct cmt_gauge *fs_files_free;
    struct cmt_gauge *fs_free_bytes;
    struct cmt_gauge *fs_readonly;
    struct cmt_gauge *fs_size_bytes;

    struct flb_regex *fs_regex_read_only;
    struct flb_regex *fs_regex_skip_mount;
    struct flb_regex *fs_regex_skip_fs_types;

    /* testfile */
    struct cmt_counter *load_errors;
};

#endif
