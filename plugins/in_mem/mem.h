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

#ifndef FLB_IN_MEM_H
#define FLB_IN_MEM_H

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#define DEFAULT_INTERVAL_SEC  "1"
#define DEFAULT_INTERVAL_NSEC "0"

struct flb_in_mem_info {
    uint64_t mem_total;
    uint64_t mem_used;
    uint64_t mem_free;
    uint64_t swap_total;
    uint64_t swap_used;
    uint64_t swap_free;
};

struct flb_in_mem_config {
    int    idx;
    int    page_size;
    int    interval_sec;
    int    interval_nsec;
    pid_t  pid;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder log_encoder;
};

#endif
