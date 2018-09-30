/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

#ifndef FLB_IN_DOCKER_H
#define FLB_IN_DOCKER_H

#define CURRENT_DIR           "."
#define PREV_DIR              ".."
#define OS_DIR_TYPE           4
#define DOCKER_LONG_ID_LEN    64
#define DOCKER_SHORT_ID_LEN   12
#define DOCKER_CGROUP_MEM_DIR "/sys/fs/cgroup/memory/docker"
#define DOCKER_CGROUP_CPU_DIR "/sys/fs/cgroup/cpu/docker"
#define DOCKER_MEM_LIMIT_FILE "memory.limit_in_bytes"
#define DOCKER_MEM_USAGE_FILE "memory.usage_in_bytes"
#define DOCKER_CPU_USAGE_FILE "cpuacct.usage"
#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0

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
    mem_snapshot *mem;
    cpu_snapshot *cpu;
    struct mk_list _head;
} docker_snapshot;

/* CPU Input configuration & context */
struct flb_in_docker_config {
    int coll_fd;                /* collector id/fd */
    int interval_sec;           /* interval collection time (Second) */
    int interval_nsec;          /* interval collection time (Nanosecond) */
    struct mk_list *whitelist;  /* dockers to monitor */
    struct mk_list *blacklist;  /* dockers to exclude */
    struct flb_input_instance *i_ins;
};

int in_docker_collect(struct flb_input_instance *i_ins,
                      struct flb_config *config, void *in_context);
extern struct flb_input_plugin in_docker_plugin;

#endif