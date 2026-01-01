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

#ifndef FLB_IN_NE_CPU_H
#define FLB_IN_NE_CPU_H

#include "ne.h"

extern struct flb_ne_collector cpu_collector;

#ifdef __linux__
#elif __APPLE__
int ne_cpu_init(struct flb_ne *ctx);
int ne_cpu_update(struct flb_ne *ctx);
static int ne_cpufreq_init(struct flb_ne *ctx)
{
    return 0;
}

static int ne_cpufreq_update(struct flb_ne *ctx)
{
    return 0;
}
#else
static int ne_cpu_init(struct flb_ne *ctx)
{
    return 0;
}

static int ne_cpu_update(struct flb_ne *ctx)
{
    return 0;
}

static int ne_cpufreq_init(struct flb_ne *ctx)
{
    return 0;
}

static int ne_cpufreq_update(struct flb_ne *ctx)
{
    return 0;
}
#endif

#endif
