/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_IN_PODMAN_METRICS_CONFIG_H
#define FLB_IN_PODMAN_METRICS_CONFIG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_jsmn.h>

#include <monkey/mk_core/mk_list.h>

/* Buffers and sizes */
#define JSON_TOKENS                     2048
#define CONTAINER_NAME_SIZE             50
#define CONTAINER_ID_SIZE               80
#define CONTAINER_METADATA_SIZE         512
#define IMAGE_NAME_SIZE                 512
#define PID_BUFFER_SIZE                 21
#define SYSFS_FILE_PATH_SIZE            512
#define PROCFS_FILE_PATH_SIZE           512
#define CGROUP_PATH_SIZE                25

/* Special paths for sysfs traversal */
#define CURRENT_DIR                     "."
#define PREV_DIR                        ".."

/* Ignored network interfaces */
#define VETH_INTERFACE                  "veth"

#define JSON_FIELD_NAMES                "names"
#define JSON_FIELD_ID                   "id"
#define JSON_FIELD_METADATA             "metadata"

#define JSON_SUBFIELD_IMAGE_NAME        "image-name\\\":\\\""
#define JSON_SUBFIELD_SIZE_IMAGE_NAME   15

#define CGROUP_V2_PATH                  "cgroup.controllers"
#define CGROUP_V1                       1
#define CGROUP_V2                       2

/* Paths in /proc subsystem */
#define PROCFS_PATH                     "/proc"
#define PROC_NET_SUFFIX                 "net/dev"

/* Paths in /sys subsystem */
#define SYSFS_PATH                      "/sys/fs/cgroup"
#define V1_SYSFS_MEMORY                 "memory"
#define V1_SYSFS_CPU                    "cpuacct"
#define V1_SYSFS_SYSTEMD                "systemd"
#define SYSFS_CONTAINER_PREFIX          "libpod"
#define SYSFS_LIBPOD_PARENT             "libpod_parent"
#define SYSFS_CONMON                    "conmon"

/* Default podman config file path, in case of not provided one */
#define PODMAN_CONFIG_DEFAULT_PATH      "/var/lib/containers/storage/overlay-containers/containers.json"

/* Markers of network values in /proc/<pid>/dev/net */
#define DEV_NET_IGNORE_LINES            2
#define DEV_NET_NAME                    0
#define DEV_NET_RX_BYTES                1
#define DEV_NET_RX_ERRORS               3
#define DEV_NET_TX_BYTES                9
#define DEV_NET_TX_ERRORS               11

/* Key names in .stat files */
#define STAT_KEY_RSS                    "rss"
#define STAT_KEY_CPU                    "usage_usec"
#define STAT_KEY_CPU_USER               "user_usec"

/* Static lists of fields in counters or gauges */
#define FIELDS_METRIC                  (char*[3]){"id", "name", "image" }
#define FIELDS_METRIC_WITH_IFACE       (char*[4]){"id", "name", "image", "interface" }

/* Files from sysfs containing required data (cgroups v1) */
#define V1_SYSFS_FILE_MEMORY           "memory.usage_in_bytes"
#define V1_SYSFS_FILE_MAX_MEMORY       "memory.max_usage_in_bytes"
#define V1_SYSFS_FILE_MEMORY_STAT      "memory.stat"
#define V1_SYSFS_FILE_MEMORY_LIMIT     "memory.limit_in_bytes"
#define V1_SYSFS_FILE_CPU_USER         "cpuacct.usage_user"
#define V1_SYSFS_FILE_CPU              "cpuacct.usage"
#define V1_SYSFS_FILE_PIDS             "cgroup.procs"

/* Files from sysfs containing required data (cgroups v2) */
#define V2_SYSFS_FILE_MEMORY           "memory.current"
#define V2_SYSFS_FILE_MAX_MEMORY       "memory.peak"
#define V2_SYSFS_FILE_MEMORY_STAT      "memory.stat"
#define V2_SYSFS_FILE_MEMORY_LIMIT     "memory.max"
#define V2_SYSFS_FILE_CPU_STAT         "cpu.stat"
#define V2_SYSFS_FILE_PIDS             "cgroup.procs"
#define V2_SYSFS_FILE_PIDS_ALT         "containers/cgroup.procs"

/* Values used to construct counters/gauges names and descriptions */
#define COUNTER_PREFIX                  "container"

#define COUNTER_MEMORY_PREFIX           "memory"
#define COUNTER_SPEC_MEMORY_PREFIX      "spec_memory"
#define COUNTER_MEMORY_USAGE            "usage_bytes"
#define DESCRIPTION_MEMORY_USAGE        "Container memory usage in bytes"
#define COUNTER_MEMORY_MAX_USAGE        "max_usage_bytes"
#define DESCRIPTION_MEMORY_MAX_USAGE    "Container max memory usage in bytes"
#define COUNTER_MEMORY_LIMIT            "limit_bytes"
#define DESCRIPTION_MEMORY_LIMIT        "Container memory limit in bytes"
#define GAUGE_MEMORY_RSS                "rss"
#define DESCRIPTION_MEMORY_RSS          "Container RSS in bytes"

#define COUNTER_CPU_PREFIX              "cpu"
#define COUNTER_CPU_USER                "user_seconds_total"
#define DESCRIPTION_CPU_USER            "Container cpu usage in seconds in user mode"
#define COUNTER_CPU                     "usage_seconds_total"
#define DESCRIPTION_CPU                 "Container cpu usage in seconds"

#define COUNTER_NETWORK_PREFIX          "network"
#define COUNTER_RX_BYTES                "receive_bytes_total"
#define DESCRIPTION_RX_BYTES            "Network received bytes"
#define COUNTER_RX_ERRORS               "receive_errors_total"
#define DESCRIPTION_RX_ERRORS           "Network received errors"
#define COUNTER_TX_BYTES                "transmit_bytes_total"
#define DESCRIPTION_TX_BYTES            "Network transmited bytes"
#define COUNTER_TX_ERRORS               "transmit_errors_total"
#define DESCRIPTION_TX_ERRORS           "Network transmitedd errors"


struct net_iface {
    flb_sds_t       name;
    uint64_t        rx_bytes;
    uint64_t        rx_errors;
    uint64_t        tx_bytes;
    uint64_t        tx_errors;
    struct mk_list  _head;
};

struct container {
    flb_sds_t       name;
    flb_sds_t       id;
    flb_sds_t       image_name;
    struct mk_list  _head;

    uint64_t        memory_usage;
    uint64_t        memory_max_usage;
    uint64_t        memory_limit;
    uint64_t        cpu;
    uint64_t        cpu_user;
    uint64_t        rss;

    struct mk_list  net_data;
};

struct sysfs_path {
    flb_sds_t       path;
    struct mk_list  _head;
};

struct flb_in_metrics {
    /* config map options */
    int scrape_on_start;
    int scrape_interval;
    flb_sds_t podman_config_path;

    /* container list */
    struct mk_list items;

    /* sysfs path list */
    struct mk_list sysfs_items;

    /* counters */
    struct cmt_counter *c_memory_usage;
    struct cmt_counter *c_memory_max_usage;
    struct cmt_counter *c_memory_limit;
    struct cmt_gauge   *g_rss;
    struct cmt_counter *c_cpu_user;
    struct cmt_counter *c_cpu;
    struct cmt_counter *rx_bytes;
    struct cmt_counter *rx_errors;
    struct cmt_counter *tx_bytes;
    struct cmt_counter *tx_errors;

    /* cgroup version used by host */
    int cgroup_version;

    /* podman config file path */
    flb_sds_t config;

    /* proc and sys paths, overwriting mostly for testing */
    flb_sds_t sysfs_path;
    flb_sds_t procfs_path;

    /* internal */
    int coll_fd_runtime;
    struct flb_input_instance *ins;
};

#endif
