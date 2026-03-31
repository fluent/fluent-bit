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

    g = cmt_gauge_create(ctx->cmt, "windows", "paging_file", "limit_megabytes",
                         "Number of bytes that can be stored in the operating system paging files. " \
                         "0 (zero) indicates that there are no paging files",
                         1, (char *[]) {"file"});

    if (!g) {
        return -1;
    }
    ctx->wmi_paging_file->limit_megabytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "paging_file", "free_megabytes",
                         "Number of bytes that can be mapped into the operating system paging files " \
                         "without causing any other pages to be swapped out",
                         1, (char *[]) {"file"});

    if (!g) {
        return -1;
    }
    ctx->wmi_paging_file->free_megabytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "paging_file", "peak_usage_megabytes",
                         "The value indicates the highest use page file (PeakUsage)",
                         1, (char *[]) {"file"});

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
    double limit_val = 0;
    char *paging_file = NULL;

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

        paging_file = we_wmi_get_property_str_value(ctx, "Name", class_obj);
        if (!paging_file) {
            continue;
        }

        limit_val = we_wmi_get_property_value(ctx, "AllocatedBaseSize", class_obj);
        cmt_gauge_set(ctx->wmi_paging_file->limit_megabytes,
                      timestamp, limit_val, 1, (char *[]){ paging_file });

        /* Calculate Free megabytes */
        val = we_wmi_get_property_value(ctx, "CurrentUsage", class_obj);
        val = limit_val - val;
        cmt_gauge_set(ctx->wmi_paging_file->free_megabytes,
                      timestamp, val, 1, (char *[]){ paging_file });

        val = we_wmi_get_property_value(ctx, "PeakUsage", class_obj);
        cmt_gauge_set(ctx->wmi_paging_file->peak_usage_megabytes,
                      timestamp, val, 1, (char *[]){ paging_file });

        class_obj->lpVtbl->Release(class_obj);
        flb_free(paging_file);
    }

    enumerator->lpVtbl->Release(enumerator);

    we_wmi_cleanup(ctx);

    return 0;
}
