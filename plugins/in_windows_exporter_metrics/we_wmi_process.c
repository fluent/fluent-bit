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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_wmi.h"
#include "we_wmi_process.h"
#include "we_util.h"
#include "we_metric.h"

static double nop_adjust(double value)
{
    return value;
}

int we_wmi_process_init(struct flb_we *ctx)
{
    struct cmt_gauge *g;

    ctx->wmi_process = flb_calloc(1, sizeof(struct we_wmi_process_counters));
    if (!ctx->wmi_process) {
        flb_errno();
        return -1;
    }
    ctx->wmi_process->operational = FLB_FALSE;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "start_time",
                         "Time of process start",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->start_time = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "handles",
                         "Total number of handles the process has open. " \
                         "This number is the sum of the handles currently " \
                         "open by each thread in the process.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->handles = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "cpu_time_total",
                        "Returns elapsed time that all of the threads of this process " \
                         "used the processor to execute instructions by mode " \
                         "(privileged, user). An instruction is the basic unit " \
                         "of execution in a computer, a thread is the object " \
                         "that executes instructions, and a process is " \
                         "the object created when a program is run. "   \
                         "Code executed to handle some hardware interrupts " \
                         "and trap conditions is included in this count.",
                         4, (char *[]) {"process", "process_id", "creating_process_id", "mode"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->cpu_time_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "io_bytes_total",
                         "Bytes issued to I/O operations in different modes "\
                         "(read, write, other).",
                         4, (char *[]) {"process", "process_id", "creating_process_id", "mode"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->io_bytes_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "io_operations_total",
                         "I/O operations issued in different modes (read, write, other).",
                         4, (char *[]) {"process", "process_id", "creating_process_id", "mode"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->io_operations_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "page_faults_total",
                         "Page faults by the threads executing in this process.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->page_faults_total = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "page_file_bytes",
                         "Current number of bytes this process has used " \
                         "in the paging file(s).",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->page_file_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "pool_bytes",
                         "Pool Bytes is the last observed number of bytes " \
                         "in the paged or nonpaged pool.",
                         4, (char *[]) {"process", "process_id", "creating_process_id", "pool"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->pool_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "priority_base",
                         "Current base priority of this process. "      \
                         "Threads within a process can raise and "      \
                         "lower their own base priority relative to "   \
                         "the process base priority of the process.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->priority_base = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "private_bytes",
                         "Current number of bytes this process has allocated " \
                         "that cannot be shared with other processes.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->private_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "thread_count",
                         "Number of threads currently active in this process.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->thread_count = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "virtual_bytes",
                         "Current size, in bytes, of the virtual address space " \
                         "that the process is using.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->virtual_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "working_set_private_bytes",
                         "Size of the working set, in bytes, that is "  \
                         "use for this process only and not shared nor " \
                         "shareable by other processes.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->working_set_private_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "working_set_peak_bytes",
                         "Maximum size, in bytes, of the Working Set of " \
                         "this process at any point in time. "          \
                         "The Working Set is the set of memory pages touched recently " \
                         "by the threads in the process.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->working_set_peak_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "process", "working_set_bytes",
                         "Maximum number of bytes in the working set of " \
                         "this process at any point in time. "          \
                         "The working set is the set of memory pages touched recently " \
                         "by the threads in the process.",
                         3, (char *[]) {"process", "process_id", "creating_process_id"});

    if (!g) {
        return -1;
    }
    ctx->wmi_process->working_set_bytes = g;

    ctx->wmi_process->info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_process->info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_process->info->metric_instance = (void *)g;
    ctx->wmi_process->info->type = CMT_GAUGE;
    ctx->wmi_process->info->value_adjuster = nop_adjust;
    ctx->wmi_process->info->wmi_counter = "Win32_PerfRawData_PerfProc_Process";
    ctx->wmi_process->info->wmi_property = "";
    ctx->wmi_process->info->label_property_count = 0;
    ctx->wmi_process->info->label_property_keys = NULL;
    ctx->wmi_process->info->where_clause = NULL;

    ctx->wmi_process->operational = FLB_TRUE;

    return 0;
}

int we_wmi_process_exit(struct flb_we *ctx)
{
    ctx->wmi_process->operational = FLB_FALSE;

    flb_free(ctx->wmi_process->info);
    flb_free(ctx->wmi_process);

    return 0;
}

static int wmi_process_regex_match(struct flb_regex *regex, char *name)
{
    if (regex == NULL) {
        return 0;
    }

    if (name == NULL) {
        return 0;
    }

    return flb_regex_match(regex, name, strlen(name));
}

int we_wmi_process_filter(char *name, struct flb_we *ctx)
{
    if (strcasestr(name, "_Total") != NULL) {
        return 1;
    }

    if (wmi_process_regex_match(ctx->denying_process_regex, name) ||
        !wmi_process_regex_match(ctx->allowing_process_regex, name)) {
        return 1;
    }

    return 0;
}

int we_wmi_process_update(struct flb_we *ctx)
{
    uint64_t timestamp = 0;
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    double val = 0;
    char *name = NULL;
    char *process_name = NULL;
    char *process_id = NULL;
    char *creating_process_id = NULL;
    double freq = 0;
    double ticks_to_seconds = 1 / 1e7;
    char *state;

    if (!ctx->wmi_process->operational) {
        flb_plg_error(ctx->ins, "process collector not yet in operational state");

        return -1;
    }

    if (FAILED(we_wmi_coinitialize(ctx))) {
        return -1;
    }

    timestamp = cfl_time_now();

    if (FAILED(we_wmi_execute_query(ctx, ctx->wmi_process->info, &enumerator))) {
        return -1;
    }

    while(enumerator) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &class_obj, &ret);

        if(ret == 0) {
            break;
        }

        name = we_wmi_get_property_str_value(ctx, "Name", class_obj);
        if (!name) {
            continue;
        }
        /* Remove # from the duplicated process names */
        process_name = strtok_s(name, "#", &state);
        if (we_wmi_process_filter(process_name, ctx) == 1) {
            flb_free(name);

            continue;
        }

        process_id = we_wmi_get_property_str_value(ctx, "IDProcess", class_obj);
        creating_process_id = we_wmi_get_property_str_value(ctx, "CreatingProcessID", class_obj);
        freq = we_wmi_get_property_value(ctx, "Frequency_Object", class_obj);

        val = we_wmi_get_property_value(ctx, "ElapsedTime", class_obj);
        cmt_gauge_set(ctx->wmi_process->start_time, timestamp,
                      (double)((val-116444736000000000)/freq),
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "HandleCount", class_obj);
        cmt_gauge_set(ctx->wmi_process->handles, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "PercentUserTime", class_obj);
        cmt_gauge_set(ctx->wmi_process->cpu_time_total, timestamp, val * ticks_to_seconds,
                      4, (char *[]) {process_name, process_id, creating_process_id, "user"});

        val = we_wmi_get_property_value(ctx, "PercentPrivilegedTime", class_obj);
        cmt_gauge_set(ctx->wmi_process->cpu_time_total, timestamp, val * ticks_to_seconds,
                      4, (char *[]) {process_name, process_id, creating_process_id, "privileged"});

        val = we_wmi_get_property_value(ctx, "IOOtherBytesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_process->io_bytes_total, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "other"});

        val = we_wmi_get_property_value(ctx, "IOOtherOperationsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_process->io_operations_total, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "other"});

        val = we_wmi_get_property_value(ctx, "IOReadBytesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_process->io_bytes_total, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "read"});

        val = we_wmi_get_property_value(ctx, "IOReadOperationsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_process->io_operations_total, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "read"});

        val = we_wmi_get_property_value(ctx, "IOWriteBytesPersec", class_obj);
        cmt_gauge_set(ctx->wmi_process->io_bytes_total, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "write"});

        val = we_wmi_get_property_value(ctx, "IOWriteOperationsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_process->io_operations_total, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "write"});

        val = we_wmi_get_property_value(ctx, "PageFaultsPersec", class_obj);
        cmt_gauge_set(ctx->wmi_process->page_faults_total, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "PageFileBytes", class_obj);
        cmt_gauge_set(ctx->wmi_process->page_file_bytes, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "PoolNonpagedBytes", class_obj);
        cmt_gauge_set(ctx->wmi_process->pool_bytes, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "nonpaged"});

        val = we_wmi_get_property_value(ctx, "PoolPagedBytes", class_obj);
        cmt_gauge_set(ctx->wmi_process->pool_bytes, timestamp, val,
                      4, (char *[]) {process_name, process_id, creating_process_id, "paged"});

        val = we_wmi_get_property_value(ctx, "PriorityBase", class_obj);
        cmt_gauge_set(ctx->wmi_process->priority_base, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "ThreadCount", class_obj);
        cmt_gauge_set(ctx->wmi_process->thread_count, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "PrivateBytes", class_obj);
        cmt_gauge_set(ctx->wmi_process->private_bytes, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "VirtualBytes", class_obj);
        cmt_gauge_set(ctx->wmi_process->virtual_bytes, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "WorkingSetPrivate", class_obj);
        cmt_gauge_set(ctx->wmi_process->working_set_private_bytes, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "WorkingSetPeak", class_obj);
        cmt_gauge_set(ctx->wmi_process->working_set_peak_bytes, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        val = we_wmi_get_property_value(ctx, "WorkingSet", class_obj);
        cmt_gauge_set(ctx->wmi_process->working_set_bytes, timestamp, val,
                      3, (char *[]) {process_name, process_id, creating_process_id});

        class_obj->lpVtbl->Release(class_obj);

        flb_free(name);
        flb_free(process_id);
        flb_free(creating_process_id);
    }

    enumerator->lpVtbl->Release(enumerator);

    we_wmi_cleanup(ctx);

    return 0;
}
