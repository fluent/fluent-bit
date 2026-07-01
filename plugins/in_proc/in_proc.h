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

#ifndef FLB_IN_PROC_H
#define FLB_IN_PROC_H

#include <stdint.h>
#include <unistd.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#define DEFAULT_INTERVAL_SEC  "1"
#define DEFAULT_INTERVAL_NSEC "0"

#define FLB_CMD_LEN 256
#define FLB_IN_PROC_NAME "in_proc"

struct flb_in_proc_mem_linux {
    uint64_t vmpeak;
    uint64_t vmsize;
    uint64_t vmlck;
    uint64_t vmhwm;
    uint64_t vmrss;
    uint64_t vmdata;
    uint64_t vmstk;
    uint64_t vmexe;
    uint64_t vmlib;
    uint64_t vmpte;
    uint64_t vmswap;
};

struct flb_in_proc_mem_offset {
    char   *key;
    char   *msgpack_key;
    size_t offset;
};

struct flb_in_proc_config {
    int  alert;
    uint8_t  alive;

    /* Checking process */
    flb_sds_t  proc_name;
    pid_t      pid;
    size_t     len_proc_name;

    /* Time interval check */
    int interval_sec;
    int interval_nsec;

    /* Memory */
    int mem;

    /* File descriptor */
    int fds;

    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

#endif /*FLB_IN_PROC_H*/
