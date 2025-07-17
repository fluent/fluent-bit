/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include <float.h>

#include "we.h"
#include "we_cpu.h"
#include "we_util.h"
#include "we_metric.h"
#include "we_perflib.h"


struct we_perflib_metric_source basic_metric_sources[] = {
        WE_PERFLIB_METRIC_SOURCE("cstate_seconds_total",
                                 "% C1 Time",
                                 "c1"),

        WE_PERFLIB_METRIC_SOURCE("cstate_seconds_total",
                                 "% C2 Time",
                                 "c2"),

        WE_PERFLIB_METRIC_SOURCE("cstate_seconds_total",
                                 "% C3 Time",
                                 "c3"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% Idle Time",
                                 "idle"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% Interrupt Time",
                                 "interrupt"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% DPC Time",
                                 "dpc"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% Privileged Time",
                                 "privileged"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% User Time",
                                 "user"),

        WE_PERFLIB_METRIC_SOURCE("interrupts_total",
                                 "Interrupts/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("dpcs_total",
                                 "DPCs Queued/sec",
                                 NULL),

        WE_PERFLIB_TERMINATOR_SOURCE()
    };


struct we_perflib_metric_source full_metric_sources[] = {
        WE_PERFLIB_METRIC_SOURCE("cstate_seconds_total",
                                 "% C1 Time",
                                 "c1"),

        WE_PERFLIB_METRIC_SOURCE("cstate_seconds_total",
                                 "% C2 Time",
                                 "c2"),

        WE_PERFLIB_METRIC_SOURCE("cstate_seconds_total",
                                 "% C3 Time",
                                 "c3"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% Idle Time",
                                 "idle"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% Interrupt Time",
                                 "interrupt"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% DPC Time",
                                 "dpc"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% Privileged Time",
                                 "privileged"),

        WE_PERFLIB_METRIC_SOURCE("time_total",
                                 "% User Time",
                                 "user"),

        WE_PERFLIB_METRIC_SOURCE("interrupts_total",
                                 "Interrupts/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("dpcs_total",
                                 "DPCs Queued/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("clock_interrupts_total",
                                 "Clock Interrupts/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("idle_break_events_total",
                                 "Idle Break Events/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("parkings_status",
                                 "Parking Status",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("core_frequency_mhz",
                                 "Processor Frequency",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("processor_performance",
                                 "% Processor Performance",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("processor_utility_total",
                                 "% Processor Utility",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("processor_privileged_utility_total",
                                 "% Privileged Utility",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("processor_mperf_total",
                                 "% Processor Performance",
                                 NULL),

        WE_PERFLIB_TERMINATOR_SOURCE()
    };

struct we_perflib_metric_spec full_metric_specs[] =
    {
        WE_PERFLIB_COUNTER_SPEC("cstate_seconds_total",
                                "Time spent in low-power idle state.",
                                "core,state"),

        WE_PERFLIB_COUNTER_SPEC("time_total",
                                "Time that processor spent in different " \
                                "modes (idle, user, system, ...)",
                                "core,mode"),

        WE_PERFLIB_COUNTER_SPEC("interrupts_total",
                                "Total number of received and serviced " \
                                "hardware interrupts",
                                "core"),

        WE_PERFLIB_COUNTER_SPEC("dpcs_total",
                                "Total number of received and serviced " \
                                "deferred procedure calls (DPCs)",
                                "core"),

        WE_PERFLIB_COUNTER_SPEC("clock_interrupts_total",
                                "Total number of received and serviced " \
                                "clock tick interrupts",
                                "core"),

        WE_PERFLIB_COUNTER_SPEC("idle_break_events_total",
                                "Total number of time processor was woken " \
                                "from idle",
                                "core"),

        WE_PERFLIB_GAUGE_SPEC("parkings_status",
                              "Parking Status represents whether a " \
                              "processor is parked or not",
                              "core"),

        WE_PERFLIB_GAUGE_SPEC("core_frequency_mhz",
                              "Core frequency in megahertz",
                              "core"),

        WE_PERFLIB_GAUGE_SPEC("processor_performance",
                              "Processor Performance is the average " \
                              "performance of the processor while it is " \
                              "executing instructions, as a percentage of" \
                              " the nominal performance of the processor." \
                              " On some processors, Processor Performance" \
                              " may exceed 100%",
                              "core"),

        WE_PERFLIB_COUNTER_SPEC("processor_utility_total",
                                "Processor Utility is the amount of time " \
                                "the core spends executing instructions",
                                "core"),

        WE_PERFLIB_COUNTER_SPEC("processor_privileged_utility_total",
                                "Processor Privileged Utility is the amount of time " \
                                "the core has spent executing instructions " \
                                "inside the kernel",
                                "core"),

        WE_PERFLIB_COUNTER_SPEC("processor_mperf_total",
                                "Processor MPerf is the number of TSC ticks " \
                                "incremented while executing instructions",
                                "core"),

        WE_PERFLIB_TERMINATOR_SPEC()
    };


int we_cpu_init(struct flb_we *ctx)
{
    struct we_perflib_metric_source *metric_sources;
    int                              result;

    ctx->cpu.operational = FLB_FALSE;

    ctx->cpu.metrics = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 64, 128);

    if (ctx->cpu.metrics == NULL) {
        flb_plg_error(ctx->ins, "could not create metrics hash table");

        return -1;
    }

    result = we_initialize_perflib_metric_specs(ctx->cmt,
                                                ctx->cpu.metrics,
                                                "windows",
                                                "cpu",
                                                &ctx->cpu.metric_specs,
                                                full_metric_specs);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize metric specs");

        return -2;
    }

    if (fabsf(ctx->windows_version - 6.05) > FLT_EPSILON) {
        metric_sources = full_metric_sources;
        ctx->cpu.query = (char *) "Processor Information";
    }
    else {
        metric_sources = basic_metric_sources;
        ctx->cpu.query = (char *) "Processor";
    }

    result = we_initialize_perflib_metric_sources(ctx->cpu.metrics,
                                                  &ctx->cpu.metric_sources,
                                                  metric_sources);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize metric sources");

        we_deinitialize_perflib_metric_specs(ctx->cpu.metric_specs);
        flb_free(ctx->cpu.metric_specs);

        return -3;
    }

    ctx->cpu.operational = FLB_TRUE;

    return 0;
}

int we_cpu_exit(struct flb_we *ctx)
{
    we_deinitialize_perflib_metric_sources(ctx->cpu.metric_sources);
    we_deinitialize_perflib_metric_specs(ctx->cpu.metric_specs);

    flb_free(ctx->cpu.metric_sources);
    flb_free(ctx->cpu.metric_specs);

    ctx->cpu.operational = FLB_FALSE;

    return 0;
}

int we_cpu_instance_hook(char *instance_name, struct flb_we *ctx)
{
    return (strcasestr(instance_name, "Total") != NULL);
}

int we_cpu_label_prepend_hook(char                           **label_list,
                              size_t                           label_list_size,
                              size_t                          *label_count,
                              struct we_perflib_metric_source *metric_source,
                              char                            *instance_name,
                              struct we_perflib_counter       *counter)
{
    if (label_count == NULL) {
        return -1;
    }

    if (*label_count >= label_list_size) {
        return -2;
    }

    label_list[(*label_count)++] = instance_name;

    return 0;
}

int we_cpu_update(struct flb_we *ctx)
{
    if (!ctx->cpu.operational) {
        flb_plg_error(ctx->ins, "cpu collector not yet in operational state");

        return -1;
    }

    return we_perflib_update_counters(ctx,
                                      ctx->cpu.query,
                                      ctx->cpu.metric_sources,
                                      we_cpu_instance_hook,
                                      we_cpu_label_prepend_hook);
}
