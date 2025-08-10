/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

/* Default enabled metrics */

#ifdef __linux__
#define NE_DEFAULT_ENABLED_METRICS "cpu,cpufreq,meminfo,diskstats,filesystem,uname,stat,time,loadavg,vmstat,netdev,sockstat,filefd,systemd,nvme,thermal_zone"
#elif __APPLE__
#define NE_DEFAULT_ENABLED_METRICS "cpu,loadavg,meminfo,diskstats,uname,netdev"
#endif

/* filesystem: regex for ignoring mount points and filesystem types */

#define IGNORED_MOUNT_POINTS "^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)"
#define IGNORED_FS_TYPES     "^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$"

/* diskstats: regex for ignoring devices */
#define IGNORED_DEVICES  "^(ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\\d+n\\d+p)\\d+$"

struct flb_ne {
    /* configuration */
    flb_sds_t path_procfs;
    flb_sds_t path_sysfs;
    flb_sds_t path_textfile;
    int scrape_interval;

    int coll_fd;                                      /* collector fd     */
    struct cmt *cmt;                                  /* cmetrics context */
    struct flb_input_instance *ins;                   /* input instance   */
    struct mk_list *metrics;                          /* enabled metrics */

    struct mk_list collectors;

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

#ifdef FLB_SYSTEM_MACOS
    /* meminfo_darwin */
    struct cmt_gauge *darwin_free_bytes;
    struct cmt_gauge *darwin_active_bytes;
    struct cmt_gauge *darwin_compressed_bytes;
    struct cmt_gauge *darwin_inactive_bytes;
    struct cmt_gauge *darwin_wired_bytes;
    struct cmt_gauge *darwin_internal_bytes;
    struct cmt_gauge *darwin_purgeable_bytes;
    struct cmt_counter *darwin_pageins_bytes;
    struct cmt_counter *darwin_pageouts_bytes;
    struct cmt_gauge *darwin_swap_used_bytes;
    struct cmt_gauge *darwin_swap_total_bytes;
    struct cmt_counter *darwin_total_bytes;
#endif

    /* diskstats: abbreviation 'dt' */
    void *dt_metrics;
    struct flb_regex *dt_regex_skip_devices;
    flb_sds_t dt_regex_skip_devices_text;

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

#ifdef FLB_SYSTEM_MACOS
    /* netdev_darwin */
    struct cmt_gauge *darwin_receive_packets;
    struct cmt_gauge *darwin_transmit_packets;
    struct cmt_gauge *darwin_receive_bytes;
    struct cmt_gauge *darwin_transmit_bytes;
    struct cmt_gauge *darwin_receive_errors;
    struct cmt_gauge *darwin_transmit_errors;
    struct cmt_gauge *darwin_receive_dropped;
    struct cmt_gauge *darwin_receive_multicast;
    struct cmt_gauge *darwin_transmit_multicast;
    struct cmt_gauge *darwin_collisions;
    struct cmt_gauge *darwin_noproto;
#endif

    /* sockstat_linux */
    struct cmt_gauge *sockstat_sockets_used;
    struct cmt_gauge *sockstat_TCP_alloc;
    struct cmt_gauge *sockstat_TCP_inuse;
    struct cmt_gauge *sockstat_TCP_mem;
    struct cmt_gauge *sockstat_TCP_mem_bytes;
    struct cmt_gauge *sockstat_TCP_orphan;
    struct cmt_gauge *sockstat_TCP_tw;
    struct cmt_gauge *sockstat_UDP_inuse;
    struct cmt_gauge *sockstat_UDP_mem;
    struct cmt_gauge *sockstat_UDP_mem_bytes;
    struct cmt_gauge *sockstat_UDPLITE_inuse;
    struct cmt_gauge *sockstat_RAW_inuse;
    struct cmt_gauge *sockstat_FRAG_inuse;
    struct cmt_gauge *sockstat_FRAG_memory;
    struct cmt_gauge *sockstat_TCP6_inuse;
    struct cmt_gauge *sockstat_UDP6_inuse;
    struct cmt_gauge *sockstat_UDPLITE6_inuse;
    struct cmt_gauge *sockstat_RAW6_inuse;
    struct cmt_gauge *sockstat_FRAG6_inuse;
    struct cmt_gauge *sockstat_FRAG6_memory;

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
    flb_sds_t fs_regex_ingore_mount_point_text;
    flb_sds_t fs_regex_ingore_filesystem_type_text;

    struct flb_regex *fs_regex_read_only;
    struct flb_regex *fs_regex_skip_mount;
    struct flb_regex *fs_regex_skip_fs_types;

    /* testfile */
    struct cmt_counter *load_errors;

    /* systemd */

    struct cmt_gauge   *systemd_socket_accepted_connections;
    struct cmt_gauge   *systemd_socket_active_connections;
    struct cmt_gauge   *systemd_socket_refused_connections;
    struct cmt_counter *systemd_service_restarts;
    struct cmt_gauge   *systemd_unit_start_times;
    struct cmt_gauge   *systemd_system_running;
    struct cmt_gauge   *systemd_timer_last_trigger_seconds;
    struct cmt_gauge   *systemd_unit_state;
    struct cmt_gauge   *systemd_unit_tasks;
    struct cmt_gauge   *systemd_unit_tasks_max;
    struct cmt_gauge   *systemd_units;
    struct cmt_gauge   *systemd_version;
    void               *systemd_dbus_handle;
    int                 systemd_initialization_flag;
    int                 systemd_include_unit_start_times;
    int                 systemd_include_service_restarts;
    int                 systemd_include_service_task_metrics;
    flb_sds_t           systemd_regex_include_list_text;
    flb_sds_t           systemd_regex_exclude_list_text;
    struct flb_regex   *systemd_regex_include_list;
    struct flb_regex   *systemd_regex_exclude_list;
    double              libsystemd_version;
    char               *libsystemd_version_text;

    /* processes */
    struct cmt_gauge   *processes_thread_alloc;
    struct cmt_gauge   *processes_threads_limit;
    struct cmt_gauge   *processes_threads_state;
    struct cmt_gauge   *processes_procs_state;
    struct cmt_gauge   *processes_pid_used;
    struct cmt_gauge   *processes_pid_max;

    /* nvme */
    struct cmt_gauge   *nvme_info;

    /* thermal zone */
    struct cmt_gauge   *thermalzone_temp;
    struct cmt_gauge   *cooling_device_cur_state;
    struct cmt_gauge   *cooling_device_max_state;
};

struct flb_ne_collector {
    const char *name;
    int coll_fd;
    int interval;
    int activated;

    /* callbacks */
    int (*cb_init) (struct flb_ne *ctx);
    int (*cb_update) (struct flb_input_instance *ins, struct flb_config *conf, void *in_context);
    int (*cb_exit) (struct flb_ne *ctx);

    struct mk_list _head;
};

#endif
