/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_IN_CPU_H
#define FLB_IN_CPU_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

/* Collection time: every 1 second (0 nanoseconds) */
#define IN_CPU_COLLECT_SEC    1
#define IN_CPU_COLLECT_NSEC   0

/* CPU Input configuration context */
struct flb_in_cpu_config {
    int n_processors;  /* number of core processors  */
    int cpu_ticks;     /* CPU ticks (Kernel setting) */
    double load_now;   /* CPU load now               */
    double load_pre;   /* CPU load previously        */
};

int in_cpu_init(struct flb_config *config);
int in_cpu_collect(void *in_context);

#endif
