/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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
#include "we_wmi_paging_file.h"
#include "we_util.h"
#include "we_metric.h"

static double nop_adjust(double value)
{
    return value;
}

int we_wmi_paging_file_init(struct flb_we *ctx)
{
    struct cmt_gauge *g;

    ctx->wmi_paging_file = flb_calloc(1, sizeof(struct we_wmi_paging_file_counters));
    if (!ctx->wmi_paging_file) {
        flb_errno();
        return -1;
    }
    ctx->wmi_paging_file->operational = FLB_FALSE;

    g = cmt_gauge_create(ctx->cmt, "windows", "paging_file", "allocated_base_size_megabytes",
                         "The value indicates the actual amount of disk space allocated "\
                         "for use with this page file (AllocatedBaseSize)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_paging_file->allocated_base_size_megabytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "paging_file", "current_usage_megabytes",
                         "The value indicates how much of the total reserved page file " \
                         "is currently in use (CurrentUsage)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_paging_file->current_usage_megabytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "paging_file", "peak_usage_megabytes",
                         "The value indicates the highest use page file (PeakUsage)",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->wmi_paging_file->peak_usage_megabytes = g;

    ctx->wmi_paging_file->info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_paging_file->info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_paging_file->info->metric_instance = (void *)g;
    ctx->wmi_paging_file->info->type = CMT_GAUGE;
    ctx->wmi_paging_file->info->value_adjuster = nop_adjust;
    ctx->wmi_paging_file->info->wmi_counter = "Win32_PageFileUsage";
    ctx->wmi_paging_file->info->wmi_property = "";
    ctx->wmi_paging_file->info->label_property_count = 0;
    ctx->wmi_paging_file->info->label_property_keys = NULL;
    ctx->wmi_paging_file->info->where_clause = NULL;

    ctx->wmi_paging_file->operational = FLB_TRUE;

    return 0;
}

int we_wmi_paging_file_exit(struct flb_we *ctx)
{
    ctx->wmi_paging_file->operational = FLB_FALSE;

    flb_free(ctx->wmi_paging_file->info);
    flb_free(ctx->wmi_paging_file);

    return 0;
}

int we_wmi_paging_file_update(struct flb_we *ctx)
{
    uint64_t timestamp = 0;
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    double val = 0;

    if (!ctx->wmi_paging_file->operational) {
        flb_plg_error(ctx->ins, "paging_file collector not yet in operational state");

        return -1;
    }

    if (FAILED(we_wmi_coinitialize(ctx))) {
        return -1;
    }

    timestamp = cfl_time_now();

    if (FAILED(we_wmi_execute_query(ctx, ctx->wmi_paging_file->info, &enumerator))) {
        return -1;
    }

    while(enumerator) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &class_obj, &ret);

        if(ret == 0) {
            break;
        }

        val = we_wmi_get_property_value(ctx, "AllocatedBaseSize", class_obj);
        cmt_gauge_set(ctx->wmi_paging_file->allocated_base_size_megabytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "CurrentUsage", class_obj);
        cmt_gauge_set(ctx->wmi_paging_file->current_usage_megabytes, timestamp, val, 0, NULL);

        val = we_wmi_get_property_value(ctx, "PeakUsage", class_obj);
        cmt_gauge_set(ctx->wmi_paging_file->peak_usage_megabytes, timestamp, val, 0, NULL);

        class_obj->lpVtbl->Release(class_obj);
    }

    enumerator->lpVtbl->Release(enumerator);

    we_wmi_cleanup(ctx);

    return 0;
}
