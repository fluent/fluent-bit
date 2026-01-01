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

#ifndef FLB_OUT_FLOWCOUNTER
#define FLB_OUT_FLOWCOUNTER

#include <fluent-bit/flb_output.h>
#include <stdint.h>

#define FLB_UNIT_SEC  "second"
#define FLB_UNIT_MIN  "minute"
#define FLB_UNIT_HOUR "hour"
#define FLB_UNIT_DAY  "day"

struct flb_out_fcount_buffer {
    time_t until;
    uint64_t counts;
    uint64_t bytes;
};

struct flb_flowcounter {
    char     *unit;
    int32_t   tick;
    int       event_based;

    struct flb_out_fcount_buffer *buf;
    int index;
    int size;

    struct flb_output_instance *ins;
};

#endif
