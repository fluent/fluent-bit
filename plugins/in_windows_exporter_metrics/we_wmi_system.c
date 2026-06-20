/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022-2026 The Fluent Bit Authors
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

#include "we.h"
#include "we_wmi.h"
#include "we_wmi_system.h"
#include "we_util.h"
#include "we_metric.h"

static double nop_adjust(double value)
{
    return value;
}

int we_wmi_system_init(struct flb_we *ctx)
{
    ctx->wmi_system = flb_calloc(1, sizeof(struct we_wmi_system_counters));
    if (!ctx->wmi_system) {
        flb_errno();
        return -1;
    }
    ctx->wmi_system->operational = FLB_FALSE;

    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "context_switches_total",
                         "Total number of context switches",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_system->context_switches = g;

    g = cmt_counter_create(ctx->cmt, "windows", "system", "exception_dispatches_total",
                           "Total number of exception_dispatches",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_system->exception_dispatches = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "processor_queue",
                           "Length of processor queues",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_system->processor_queue = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "system_calls_total",
                           "Total number of system calls",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_system->system_calls = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "system_up_time",
                           "System boot time",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_system->system_up_time = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "system", "threads",
                           "Current number of threads",
                           0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_system->threads = g;

    ctx->wmi_system->info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_system->info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_system->info->metric_instance = (void *)g;
    ctx->wmi_system->info->type = CMT_GAUGE;
    ctx->wmi_system->info->value_adjuster = nop_adjust;
    ctx->wmi_system->info->wmi_counter = "Win32_PerfFormattedData_PerfOS_System";
    ctx->wmi_system->info->wmi_property = "";
    ctx->wmi_system->info->label_property_count = 0;
    ctx->wmi_system->info->label_property_keys = NULL;
    ctx->wmi_system->info->where_clause = NULL;

    ctx->wmi_system->operational = FLB_TRUE;

    return 0;
}

int we_wmi_system_exit(struct flb_we *ctx)
{
    ctx->wmi_system->operational = FLB_FALSE;

    flb_free(ctx->wmi_system->info);
    flb_free(ctx->wmi_system);

    return 0;
}

int we_wmi_system_update(struct flb_we *ctx)
{
    uint64_t timestamp = 0;
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    double val = 0;

    if (!ctx->wmi_system->operational) {
        flb_plg_error(ctx->ins, "system collector not yet in operational state");

        return -1;
    }

    if (FAILED(we_wmi_coinitialize(ctx))) {
        return -1;
    }

    timestamp = cfl_time_now();

    if (FAILED(we_wmi_execute_query(ctx, ctx->wmi_system->info, &enumerator))) {
        return -1;
    }

    while(enumerator) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &class_obj, &ret);

        if(0 == ret) {
            break;
        }

        val = we_wmi_get_property_value(ctx, "ContextSwitchesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_system->context_switches, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "ExceptionDispatchesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_system->exception_dispatches, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "ProcessorQueueLength", class_obj);
        cmt_gauge_set(ctx->wmi_system->processor_queue, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemCallsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_system->system_calls, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "SystemUpTime", class_obj);
        cmt_gauge_set(ctx->wmi_system->system_up_time, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "Threads", class_obj);
        cmt_gauge_set(ctx->wmi_system->threads, timestamp, val, 0, NULL);

        class_obj->lpVtbl->Release(class_obj);
    }

    enumerator->lpVtbl->Release(enumerator);

    we_wmi_cleanup(ctx);

    return 0;
}
