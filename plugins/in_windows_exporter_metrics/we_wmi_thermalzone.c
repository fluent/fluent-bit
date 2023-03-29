/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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
#include "we_wmi_thermalzone.h"
#include "we_util.h"
#include "we_metric.h"

static double adjust_celsius(double value)
{
    return (value/10.0) - 273.15;
}

static double nop_adjust(double value)
{
    return value;
}

int we_wmi_thermalzone_init(struct flb_we *ctx)
{
    ctx->wmi_thermals = flb_calloc(1, sizeof(struct we_wmi_thermal_counters));
    if (!ctx->wmi_thermals) {
        flb_errno();
        return -1;
    }
    ctx->wmi_thermals->operational = FLB_FALSE;

    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "windows", "thermalzone", "temperature_celsius",
                         "Temperature of the sensor device.",
                         1, (char *[]) {"name"});
    if (!g) {
        return -1;
    }

    ctx->wmi_thermals->temperature_celsius = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_thermals->temperature_celsius) {
        return -1;
    }
    ctx->wmi_thermals->temperature_celsius->label_property_keys = (char **) flb_calloc(1, sizeof(char *));
    if (!ctx->wmi_thermals->temperature_celsius->label_property_keys) {
        return -1;
    }

    ctx->wmi_thermals->temperature_celsius->metric_instance = (void *)g;
    ctx->wmi_thermals->temperature_celsius->type = CMT_GAUGE;
    ctx->wmi_thermals->temperature_celsius->value_adjuster = adjust_celsius;
    ctx->wmi_thermals->temperature_celsius->wmi_counter = "Win32_PerfRawData_Counters_ThermalZoneInformation";
    ctx->wmi_thermals->temperature_celsius->wmi_property = "HighPrecisionTemperature";
    ctx->wmi_thermals->temperature_celsius->label_property_count = 1;
    ctx->wmi_thermals->temperature_celsius->label_property_keys[0] = "name" ;

    g = cmt_gauge_create(ctx->cmt, "windows", "thermalzone", "percent_passive_limit",
                         "The limit of passive limit (percent).",
                         1, (char *[]) {"name"});
    if (!g) {
        return -1;
    }

    ctx->wmi_thermals->percent_passive_limit = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_thermals->percent_passive_limit) {
        flb_errno();
        return -1;
    }

    ctx->wmi_thermals->percent_passive_limit->label_property_keys = (char **) flb_calloc(1, sizeof(char *));
    if (!ctx->wmi_thermals->percent_passive_limit->label_property_keys) {
        flb_errno();
        return -1;
    }

    ctx->wmi_thermals->percent_passive_limit->metric_instance = (void *)g;
    ctx->wmi_thermals->percent_passive_limit->type = CMT_GAUGE;
    ctx->wmi_thermals->percent_passive_limit->value_adjuster = nop_adjust;
    ctx->wmi_thermals->percent_passive_limit->wmi_counter = "Win32_PerfRawData_Counters_ThermalZoneInformation";
    ctx->wmi_thermals->percent_passive_limit->wmi_property = "PercentPassiveLimit";
    ctx->wmi_thermals->percent_passive_limit->label_property_count = 1;
    ctx->wmi_thermals->percent_passive_limit->label_property_keys[0] = "name";

    g = cmt_gauge_create(ctx->cmt, "windows", "thermalzone", "throttle_reasons",
                         "The reason of throttle.",
                         1, (char *[]) {"name"});
    if (!g) {
        return -1;
    }
    ctx->wmi_thermals->throttle_reasons = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_thermals->throttle_reasons) {
        flb_errno();
        return -1;
    }
    ctx->wmi_thermals->throttle_reasons->label_property_keys = (char **) flb_calloc(1, sizeof(char *));
    if (!ctx->wmi_thermals->throttle_reasons->label_property_keys) {
        flb_errno();
        return -1;
    }

    ctx->wmi_thermals->throttle_reasons->metric_instance = (void *)g;
    ctx->wmi_thermals->throttle_reasons->type = CMT_GAUGE;
    ctx->wmi_thermals->throttle_reasons->value_adjuster = nop_adjust;
    ctx->wmi_thermals->throttle_reasons->wmi_counter = "Win32_PerfRawData_Counters_ThermalZoneInformation";
    ctx->wmi_thermals->throttle_reasons->wmi_property = "ThrottleReasons";
    ctx->wmi_thermals->throttle_reasons->label_property_count = 1;
    ctx->wmi_thermals->throttle_reasons->label_property_keys[0] = "name";

    ctx->wmi_thermals->operational = FLB_TRUE;

    return 0;
}

int we_wmi_thermalzone_exit(struct flb_we *ctx)
{
    flb_free(ctx->wmi_thermals->temperature_celsius->label_property_keys);
    flb_free(ctx->wmi_thermals->temperature_celsius);
    flb_free(ctx->wmi_thermals->percent_passive_limit->label_property_keys);
    flb_free(ctx->wmi_thermals->percent_passive_limit);
    flb_free(ctx->wmi_thermals->throttle_reasons->label_property_keys);
    flb_free(ctx->wmi_thermals->throttle_reasons);
    flb_free(ctx->wmi_thermals);

    return 0;
}

int we_wmi_thermalzone_update(struct flb_we *ctx)
{
    if (!ctx->wmi_thermals->operational) {
        flb_plg_error(ctx->ins, "thermalzone collector not yet in operational state");

        return -1;
    }

    if (FAILED(we_wmi_query(ctx, ctx->wmi_thermals->temperature_celsius))) {
        return -1;
    }

    if (FAILED(we_wmi_query(ctx, ctx->wmi_thermals->percent_passive_limit))) {
        return -1;
    }

    if (FAILED(we_wmi_query(ctx, ctx->wmi_thermals->throttle_reasons))) {
        return -1;
    }

    return 0;
}
