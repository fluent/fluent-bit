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

#ifndef FLB_IN_DOCKER_H
#define FLB_IN_DOCKER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log_event_encoder.h>

/* Distinguish cgroup v2 or v1 */
#define SYSFS_FILE_PATH_SIZE            512

#define DEFAULT_SYSFS_PATH              "/sys/fs/cgroup"
#define DEFAULT_CONTAINERS_PATH         "/var/lib/docker/containers"
#define CGROUP_V2_PATH                  "cgroup.controllers"
#define CGROUP_V1                       1
#define CGROUP_V2                       2

#define CURRENT_DIR           "."
#define PREV_DIR              ".."
#define OS_DIR_TYPE           4
#define DOCKER_LONG_ID_LEN    64
#define DOCKER_SHORT_ID_LEN   12

#define DOCKER_CGROUP_V2_LONG_ID_LEN 77 /* docker-CONTAINERID.scope: 7 + 64 + 6 */

/* Files from sysfs containing metrics (cgroups v1) */
#define DOCKER_CGROUP_V1_MEM_DIR "memory/docker"
#define DOCKER_CGROUP_V1_CPU_DIR "cpu/docker"
#define DOCKER_CGROUP_V1_MEM_LIMIT_FILE "memory.limit_in_bytes"
#define DOCKER_CGROUP_V1_MEM_USAGE_FILE "memory.usage_in_bytes"
#define DOCKER_CGROUP_V1_CPU_USAGE_FILE "cpuacct.usage"

/* Files from sysfs containing metrics (cgroups v2) */
#define DOCKER_CGROUP_V2_DOCKER_SERVICE_DIR "system.slice"
#define DOCKER_CGROUP_V2_MEM_USAGE_FILE     "memory.current"
#define DOCKER_CGROUP_V2_MEM_MAX_FILE       "memory.max"
#define DOCKER_CGROUP_V2_CPU_USAGE_FILE     "cpu.stat"
#define DOCKER_CGROUP_V2_CPU_USAGE_KEY      "usage_usec"
#define DOCKER_CGROUP_V2_CPU_USAGE_TEMPLATE DOCKER_CGROUP_V2_CPU_USAGE_KEY" %lu"

#define DOCKER_CONFIG_JSON    "config.v2.json"
#define DOCKER_NAME_ARG       "\"Name\""
#define DEFAULT_INTERVAL_SEC  "1"
#define DEFAULT_INTERVAL_NSEC "0"

typedef struct docker_info {
    char *id;
    struct mk_list _head;
} docker_info;

typedef struct cpu_snapshot {
    unsigned long used;
} cpu_snapshot;

typedef struct mem_snapshot {
    uint64_t limit;
    uint64_t used;
} mem_snapshot;

typedef struct docker_snapshot {
    char *id;
    char *name;
    mem_snapshot *mem;
    cpu_snapshot *cpu;
    struct mk_list _head;
} docker_snapshot;

struct flb_docker;

struct cgroup_api {
    int cgroup_version;
    struct mk_list* (*get_active_docker_ids) (struct flb_docker *);
    char*           (*get_container_name) (struct flb_docker *, char *);
    cpu_snapshot*   (*get_cpu_snapshot)   (struct flb_docker *, char *);
    mem_snapshot*   (*get_mem_snapshot)   (struct flb_docker *, char *);
};
int in_docker_set_cgroup_api_v1(struct cgroup_api *api);
int in_docker_set_cgroup_api_v2(struct cgroup_api *api);

/* Docker Input configuration & context */
struct flb_docker {
    int coll_fd;                /* collector id/fd */
    int interval_sec;           /* interval collection time (Second) */
    int interval_nsec;          /* interval collection time (Nanosecond) */
    struct mk_list *whitelist;  /* dockers to monitor */
    struct mk_list *blacklist;  /* dockers to exclude */
    struct cgroup_api cgroup_api;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder log_encoder;

    /* cgroup version used by host */
    int cgroup_version;

    /* sys path, overwriting mostly for testing */
    flb_sds_t sysfs_path;
    flb_sds_t containers_path;
};

int in_docker_collect(struct flb_input_instance *i_ins,
                      struct flb_config *config, void *in_context);
docker_info *in_docker_init_docker_info(char *id);
#endif
