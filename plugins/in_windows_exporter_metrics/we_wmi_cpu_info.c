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
#include "we_wmi_cpu_info.h"
#include "we_util.h"
#include "we_metric.h"

static double nop_adjust(double value)
{
    return value;
}

int we_wmi_cpu_info_init(struct flb_we *ctx)
{
    ctx->wmi_cpu_info = flb_calloc(1, sizeof(struct we_wmi_cpu_info_counters));
    if (!ctx->wmi_cpu_info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_cpu_info->operational = FLB_FALSE;

    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "windows", "", "cpu_info",
                         "Labeled CPU information provided by WMI Win32_Processor",
                         7, (char *[]) {"architecture",
                                        "device_id",
                                        "description",
                                        "family",
                                        "l2_cache_size",
                                        "l3_cache_size",
                                        "name"});
    if (!g) {
        return -1;
    }

    ctx->wmi_cpu_info->info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_cpu_info->info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_cpu_info->info->label_property_keys = (char **) flb_calloc(7, sizeof(char *));
    if (!ctx->wmi_cpu_info->info->label_property_keys) {
        flb_errno();
        return -1;
    }

    ctx->wmi_cpu_info->info->metric_instance = (void *)g;
    ctx->wmi_cpu_info->info->type = CMT_GAUGE;
    ctx->wmi_cpu_info->info->value_adjuster = nop_adjust;
    ctx->wmi_cpu_info->info->wmi_counter = "Win32_Processor";
    /* This metrics does not retrieve metrics values. Filled out as
     * 1.0. */
    ctx->wmi_cpu_info->info->wmi_property = "";
    ctx->wmi_cpu_info->info->label_property_count = 7;
    ctx->wmi_cpu_info->info->label_property_keys[0] = "architecture" ;
    ctx->wmi_cpu_info->info->label_property_keys[1] = "deviceid" ;
    ctx->wmi_cpu_info->info->label_property_keys[2] = "description" ;
    ctx->wmi_cpu_info->info->label_property_keys[3] = "family" ;
    ctx->wmi_cpu_info->info->label_property_keys[4] = "l2cachesize" ;
    ctx->wmi_cpu_info->info->label_property_keys[5] = "l3cachesize" ;
    ctx->wmi_cpu_info->info->label_property_keys[6] = "name" ;
    ctx->wmi_cpu_info->info->where_clause = NULL;

    ctx->wmi_cpu_info->operational = FLB_TRUE;

    return 0;
}

int we_wmi_cpu_info_exit(struct flb_we *ctx)
{
    flb_free(ctx->wmi_cpu_info->info->label_property_keys);
    flb_free(ctx->wmi_cpu_info->info);
    flb_free(ctx->wmi_cpu_info);

    return 0;
}

int we_wmi_cpu_info_update(struct flb_we *ctx)
{
    if (!ctx->wmi_cpu_info->operational) {
        flb_plg_error(ctx->ins, "cpu_info collector not yet in operational state");

        return -1;
    }

    if (FAILED(we_wmi_query_fixed_val(ctx, ctx->wmi_cpu_info->info))) {
        return -1;
    }

    return 0;
}
