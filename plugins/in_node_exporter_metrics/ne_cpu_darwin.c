/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <mach/mach_init.h>
#include <mach/mach_host.h>
#include <mach/host_info.h>
#include <TargetConditionals.h>
#if TARGET_OS_MAC
#include <libproc.h>
#endif
#include <mach/processor_info.h>
#include <mach/vm_map.h>

/*
 * CPU stats from host_processor_info()
 *
 * https://developer.apple.com/documentation/kernel/1502854-host_processor_info
 * ---------------------------
 */
static inline int cpu_stat_init(struct flb_ne *ctx)
{
    struct cmt_counter *c;

    c = cmt_counter_create(ctx->cmt, "node", "cpu", "seconds_total",
                           "Seconds the CPUs spent in each mode.",
                           2, (char *[]) {"cpu", "mode"});
    if (!c) {
        return -1;
    }
    ctx->cpu_seconds = c;

    return 0;
}

static int ne_cpu_init(struct flb_ne *ctx)
{
    int ret;

    /* CPU Stats */
    ret = cpu_stat_init(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not initialize cpu_stat metrics");
        return -1;
    }

    return 0;
}

static int cpu_stat_update(struct flb_ne *ctx, uint64_t ts)
{
    int i;
    mach_msg_type_number_t count;
    processor_cpu_load_info_t pinfo;
    natural_t ncpu;
    kern_return_t err;
    char cpu_id[8];
    double clock_per_sec = CLK_TCK;

    err = host_processor_info(mach_host_self(),
                              PROCESSOR_CPU_LOAD_INFO,
                              &ncpu,
                              (processor_info_array_t *)(&pinfo),
                              &count);

    if (err != KERN_SUCCESS) {
        flb_plg_error(ctx->ins, "host_processor_info() is failed with error = %d", err);
        return -1;
    }

    for (i = 0; i < ncpu; i++) {
        snprintf(cpu_id, sizeof(cpu_id), "%d", i);

        /* CPU seconds */
        cmt_counter_set(ctx->cpu_seconds, ts,
                        pinfo[i].cpu_ticks[CPU_STATE_USER]/clock_per_sec,
                        2, (char *[]) {cpu_id, "user"});

        cmt_counter_set(ctx->cpu_seconds, ts,
                        pinfo[i].cpu_ticks[CPU_STATE_SYSTEM]/clock_per_sec,
                        2, (char *[]) {cpu_id, "system"});

        cmt_counter_set(ctx->cpu_seconds, ts,
                        pinfo[i].cpu_ticks[CPU_STATE_NICE]/clock_per_sec,
                        2, (char *[]) {cpu_id, "nice"});

        cmt_counter_set(ctx->cpu_seconds, ts,
                        pinfo[i].cpu_ticks[CPU_STATE_IDLE]/clock_per_sec,
                        2, (char *[]) {cpu_id, "idle"});
    }

    vm_deallocate(mach_task_self(), (vm_address_t)pinfo,
                  (vm_size_t)sizeof(*pinfo) * ncpu);

    return 0;
}

static int ne_cpu_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    uint64_t ts;
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    ts = cfl_time_now();

    cpu_stat_update(ctx, ts);

    return 0;
}

struct flb_ne_collector cpu_collector = {
    .name = "cpu",
    .cb_init = ne_cpu_init,
    .cb_update = ne_cpu_update,
    .cb_exit = NULL
};
