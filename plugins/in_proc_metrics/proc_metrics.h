////* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#ifndef FLB_IN_METRICS_H
#define FLB_IN_METRICS_H

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_network.h>

struct proc_metrics_ctx
{
    int coll_id;                    /* collector id */
    pid_t pid;                      /* process id to monitor */
    char *proc_name;                /* process name used for querying each tick */
    char *process;                  /* process name or id to monitor */
    struct flb_parser *parser;
    struct flb_input_instance *ins; /* Input plugin instace */
    struct mk_list procs;
    struct cmt *cmt;

    uint64_t cpu_user_time;
    uint64_t cpu_nice_time;
    uint64_t cpu_system_time;
    uint64_t cpu_idle_time;
};

#define FLB_CMD_LEN 256

struct proc_entry {
    pid_t pid;
    struct mk_list _head;
};

struct proc_metrics_pid_cmt {
    pid_t pid;
    char cmdline[FLB_CMD_LEN];
    /* rchar: 260189
     * wchar: 413454
     * syscr: 2036
     * syscw: 2564
     * read_bytes: 0
     * write_bytes: 0
     * cancelled_write_bytes: 0
     */
    struct cmt_counter *rchar;
    struct cmt_counter *wchar;
    struct cmt_counter *syscr;
    struct cmt_counter *syscw;
    struct cmt_counter *read_bytes;
    struct cmt_counter *write_bytes;
    struct cmt_counter *cancelled_write_bytes;

    struct cmt_gauge *size;
    struct cmt_gauge *resident;
    struct cmt_gauge *shared;
    struct cmt_gauge *trs;
    struct cmt_gauge *lrs;
    struct cmt_gauge *drs;
    struct cmt_gauge *dt;

    struct cmt_counter *cpu_user_time;
    struct cmt_counter *cpu_system_time;

    struct cmt_gauge *cpu_user_percent;
    struct cmt_gauge *cpu_system_percent;
    struct cmt_gauge *cpu_percent;

    struct mk_list _head;
};

struct proc_metrics_io_status
{
    uint64_t rchar;
    uint64_t wchar;
    uint64_t syscr;
    uint64_t syscw;
    uint64_t read_bytes;
    uint64_t write_bytes;
    uint64_t cancelled_write_bytes;
};

struct proc_metrics_mem_status
{
    uint64_t size;
    uint64_t resident;
    uint64_t shared;
    uint64_t trs;
    uint64_t lrs;
    uint64_t drs;
    uint64_t dt;
};

struct proc_metrics_cpu_status
{
    uint64_t cpu_user_time;
    uint64_t cpu_system_time;
};

struct proc_metrics_status {
    struct proc_metrics_io_status io;
    struct proc_metrics_mem_status mem;
    struct proc_metrics_cpu_status cpu;
};

#endif
