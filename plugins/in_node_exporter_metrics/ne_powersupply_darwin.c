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

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>

#include "ne.h"

static int cf_number_to_double(CFTypeRef value, double *out)
{
    if (value == NULL || CFGetTypeID(value) != CFNumberGetTypeID()) {
        return -1;
    }

    if (!CFNumberGetValue((CFNumberRef) value, kCFNumberDoubleType, out)) {
        return -1;
    }

    return 0;
}

static int cf_boolean_to_double(CFTypeRef value, double *out)
{
    if (value == NULL || CFGetTypeID(value) != CFBooleanGetTypeID()) {
        return -1;
    }

    *out = CFBooleanGetValue((CFBooleanRef) value) ? 1.0 : 0.0;
    return 0;
}

static int set_numeric_metric(struct cmt_gauge *gauge,
                              CFDictionaryRef description,
                              CFStringRef key,
                              uint64_t ts,
                              const char *name,
                              double divisor)
{
    CFTypeRef value;
    double out;
    char *labels[] = {(char *) name};

    value = CFDictionaryGetValue(description, key);
    if (cf_number_to_double(value, &out) == -1) {
        return -1;
    }

    cmt_gauge_set(gauge, ts, out / divisor, 1, labels);
    return 0;
}

static int set_boolean_metric(struct cmt_gauge *gauge,
                              CFDictionaryRef description,
                              CFStringRef key,
                              uint64_t ts,
                              const char *name)
{
    CFTypeRef value;
    double out;
    char *labels[] = {(char *) name};

    value = CFDictionaryGetValue(description, key);
    if (cf_boolean_to_double(value, &out) == -1) {
        return -1;
    }

    cmt_gauge_set(gauge, ts, out, 1, labels);
    return 0;
}

static int update_power_source(struct flb_ne *ctx,
                               CFTypeRef source,
                               CFTypeRef info,
                               uint64_t ts)
{
    CFDictionaryRef description;
    CFTypeRef name_value;
    char name[128];
    CFTypeRef battery_health_value;
    char battery_health[64];
    char *health_labels_good[] = {name, "Good"};
    char *health_labels_fair[] = {name, "Fair"};
    char *health_labels_poor[] = {name, "Poor"};

    (void) ctx;

    description = IOPSGetPowerSourceDescription(info, source);
    if (description == NULL) {
        return -1;
    }

    name_value = CFDictionaryGetValue(description, CFSTR(kIOPSNameKey));
    if (name_value == NULL || CFGetTypeID(name_value) != CFStringGetTypeID()) {
        return -1;
    }

    if (!CFStringGetCString((CFStringRef) name_value, name,
                            sizeof(name), kCFStringEncodingUTF8)) {
        return -1;
    }

    set_numeric_metric(ctx->darwin_ps_current_capacity, description, CFSTR(kIOPSCurrentCapacityKey), ts, name, 1.0);
    set_numeric_metric(ctx->darwin_ps_max_capacity, description, CFSTR(kIOPSMaxCapacityKey), ts, name, 1.0);
    set_numeric_metric(ctx->darwin_ps_design_capacity, description, CFSTR(kIOPSDesignCapacityKey), ts, name, 1.0);
    set_numeric_metric(ctx->darwin_ps_nominal_capacity, description, CFSTR(kIOPSNominalCapacityKey), ts, name, 1.0);
    set_numeric_metric(ctx->darwin_ps_time_to_empty, description, CFSTR(kIOPSTimeToEmptyKey), ts, name, (1.0 / 60.0));
    set_numeric_metric(ctx->darwin_ps_time_to_full, description, CFSTR(kIOPSTimeToFullChargeKey), ts, name, (1.0 / 60.0));
    set_numeric_metric(ctx->darwin_ps_voltage, description, CFSTR(kIOPSVoltageKey), ts, name, 1000.0);
    set_numeric_metric(ctx->darwin_ps_current, description, CFSTR(kIOPSCurrentKey), ts, name, 1000.0);
    set_numeric_metric(ctx->darwin_ps_temperature, description, CFSTR(kIOPSTemperatureKey), ts, name, 1.0);

    set_boolean_metric(ctx->darwin_ps_present, description, CFSTR(kIOPSIsPresentKey), ts, name);
    set_boolean_metric(ctx->darwin_ps_charging, description, CFSTR(kIOPSIsChargingKey), ts, name);
    set_boolean_metric(ctx->darwin_ps_charged, description, CFSTR(kIOPSIsChargedKey), ts, name);
    set_boolean_metric(ctx->darwin_ps_internal_failure, description, CFSTR(kIOPSInternalFailureKey), ts, name);

    battery_health_value = CFDictionaryGetValue(description, CFSTR(kIOPSBatteryHealthKey));
    if (battery_health_value != NULL &&
        CFGetTypeID(battery_health_value) == CFStringGetTypeID() &&
        CFStringGetCString((CFStringRef) battery_health_value, battery_health,
                           sizeof(battery_health), kCFStringEncodingUTF8)) {
        cmt_gauge_set(ctx->darwin_ps_battery_health, ts, strcmp(battery_health, "Good") == 0 ? 1.0 : 0.0,
                      2, health_labels_good);
        cmt_gauge_set(ctx->darwin_ps_battery_health, ts, strcmp(battery_health, "Fair") == 0 ? 1.0 : 0.0,
                      2, health_labels_fair);
        cmt_gauge_set(ctx->darwin_ps_battery_health, ts, strcmp(battery_health, "Poor") == 0 ? 1.0 : 0.0,
                      2, health_labels_poor);
    }

    return 0;
}

static int ne_powersupply_init(struct flb_ne *ctx)
{
    char *label[] = {"power_supply"};

    ctx->darwin_ps_current_capacity = cmt_gauge_create(ctx->cmt, "node", "powersupply", "current_capacity",
                                           "Current battery capacity.", 1, label);
    if (ctx->darwin_ps_current_capacity == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_current_capacity");
        return -1;
    }

    ctx->darwin_ps_max_capacity = cmt_gauge_create(ctx->cmt, "node", "powersupply", "max_capacity",
                                       "Maximum battery capacity.", 1, label);
    if (ctx->darwin_ps_max_capacity == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_max_capacity");
        return -1;
    }

    ctx->darwin_ps_design_capacity = cmt_gauge_create(ctx->cmt, "node", "powersupply", "design_capacity",
                                          "Design battery capacity.", 1, label);
    if (ctx->darwin_ps_design_capacity == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_design_capacity");
        return -1;
    }

    ctx->darwin_ps_nominal_capacity = cmt_gauge_create(ctx->cmt, "node", "powersupply", "nominal_capacity",
                                           "Nominal battery capacity.", 1, label);
    if (ctx->darwin_ps_nominal_capacity == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_nominal_capacity");
        return -1;
    }

    ctx->darwin_ps_time_to_empty = cmt_gauge_create(ctx->cmt, "node", "powersupply", "time_to_empty_seconds",
                                        "Estimated time to empty in seconds.", 1, label);
    if (ctx->darwin_ps_time_to_empty == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_time_to_empty_seconds");
        return -1;
    }

    ctx->darwin_ps_time_to_full = cmt_gauge_create(ctx->cmt, "node", "powersupply", "time_to_full_seconds",
                                       "Estimated time to full charge in seconds.", 1, label);
    if (ctx->darwin_ps_time_to_full == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_time_to_full_seconds");
        return -1;
    }

    ctx->darwin_ps_voltage = cmt_gauge_create(ctx->cmt, "node", "powersupply", "voltage_volt",
                                  "Battery voltage in volts.", 1, label);
    if (ctx->darwin_ps_voltage == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_voltage_volt");
        return -1;
    }

    ctx->darwin_ps_current = cmt_gauge_create(ctx->cmt, "node", "powersupply", "current_ampere",
                                  "Battery current in amperes.", 1, label);
    if (ctx->darwin_ps_current == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_current_ampere");
        return -1;
    }

    ctx->darwin_ps_temperature = cmt_gauge_create(ctx->cmt, "node", "powersupply", "temp_celsius",
                                      "Battery temperature in celsius.", 1, label);
    if (ctx->darwin_ps_temperature == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_temp_celsius");
        return -1;
    }

    ctx->darwin_ps_present = cmt_gauge_create(ctx->cmt, "node", "powersupply", "present",
                                  "Power supply present status.", 1, label);
    if (ctx->darwin_ps_present == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_present");
        return -1;
    }

    ctx->darwin_ps_charging = cmt_gauge_create(ctx->cmt, "node", "powersupply", "charging",
                                   "Power supply charging status.", 1, label);
    if (ctx->darwin_ps_charging == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_charging");
        return -1;
    }

    ctx->darwin_ps_charged = cmt_gauge_create(ctx->cmt, "node", "powersupply", "charged",
                                  "Power supply charged status.", 1, label);
    if (ctx->darwin_ps_charged == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_charged");
        return -1;
    }

    ctx->darwin_ps_internal_failure = cmt_gauge_create(ctx->cmt, "node", "powersupply", "internal_failure",
                                           "Power supply internal failure status.", 1, label);
    if (ctx->darwin_ps_internal_failure == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_internal_failure");
        return -1;
    }

    ctx->darwin_ps_battery_health = cmt_gauge_create(ctx->cmt, "node", "powersupply", "battery_health",
                                         "Power supply battery health status.", 2,
                                         (char *[]) {"power_supply", "state"});
    if (ctx->darwin_ps_battery_health == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_powersupply_battery_health");
        return -1;
    }

    return 0;
}

static int ne_powersupply_update(struct flb_input_instance *ins,
                                 struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx;
    uint64_t ts;
    CFTypeRef info;
    CFArrayRef list;
    CFIndex i;

    (void) ins;
    (void) config;

    ctx = in_context;
    ts = cfl_time_now();

    info = IOPSCopyPowerSourcesInfo();
    if (info == NULL) {
        return -1;
    }

    list = IOPSCopyPowerSourcesList(info);
    if (list == NULL) {
        CFRelease(info);
        return -1;
    }

    for (i = 0; i < CFArrayGetCount(list); i++) {
        update_power_source(ctx, CFArrayGetValueAtIndex(list, i), info, ts);
    }

    CFRelease(list);
    CFRelease(info);

    return 0;
}

struct flb_ne_collector powersupply_collector = {
    .name = "powersupplyclass",
    .cb_init = ne_powersupply_init,
    .cb_update = ne_powersupply_update,
    .cb_exit = NULL
};
