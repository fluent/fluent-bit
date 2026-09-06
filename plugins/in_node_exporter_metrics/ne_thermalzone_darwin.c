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
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/sysctl.h>

#include "ne.h"

#if defined(__arm64__) || defined(__aarch64__)

/* These temperature APIs are exported by IOKit but omitted from its public headers. */
typedef struct __IOHIDEventSystemClient *IOHIDEventSystemClientRef;
typedef struct __IOHIDServiceClient *IOHIDServiceClientRef;
typedef struct __IOHIDEvent *IOHIDEventRef;

#define NE_IOHID_EVENT_TYPE_TEMPERATURE 15
#define NE_IOHID_EVENT_FIELD_BASE(type) ((type) << 16)
#define NE_ABSOLUTE_ZERO_CELSIUS -273.15

IOHIDEventSystemClientRef IOHIDEventSystemClientCreate(CFAllocatorRef allocator);
void IOHIDEventSystemClientSetMatching(IOHIDEventSystemClientRef client,
                                       CFDictionaryRef matching);
CFArrayRef IOHIDEventSystemClientCopyServices(IOHIDEventSystemClientRef client);
IOHIDEventRef IOHIDServiceClientCopyEvent(IOHIDServiceClientRef service,
                                          int64_t type,
                                          int32_t options,
                                          int64_t timestamp);
double IOHIDEventGetFloatValue(IOHIDEventRef event, int32_t field);
CFTypeRef IOHIDServiceClientCopyProperty(IOHIDServiceClientRef service,
                                         CFStringRef key);

#endif

static int read_thermal_number(CFDictionaryRef status,
                               CFStringRef key,
                               double *result)
{
    double value;
    CFTypeRef entry;

    entry = CFDictionaryGetValue(status, key);
    if (entry == NULL || CFGetTypeID(entry) != CFNumberGetTypeID()) {
        return -1;
    }

    if (!CFNumberGetValue((CFNumberRef) entry, kCFNumberDoubleType, &value)) {
        return -1;
    }
    else if (!isfinite(value)) {
        return -1;
    }

    *result = value;

    return 0;
}

static int set_thermal_metric(struct flb_ne *ctx,
                              struct cmt_gauge **gauge,
                              CFDictionaryRef status,
                              CFStringRef key,
                              char *metric_name,
                              char *help,
                              uint64_t timestamp,
                              double divisor,
                              double minimum,
                              double maximum)
{
    double value;

    if (read_thermal_number(status, key, &value) != 0) {
        return 0;
    }

    if (value < minimum || value > maximum) {
        flb_plg_warn(ctx->ins, "ignoring invalid %s value: %f", metric_name, value);
        return 0;
    }

    if (*gauge == NULL) {
        *gauge = cmt_gauge_create(ctx->cmt, "node", "thermal", metric_name,
                                  help, 0, NULL);
    }

    if (*gauge == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_thermal_%s", metric_name);
        return -1;
    }

    cmt_gauge_set(*gauge, timestamp, value / divisor, 0, NULL);

    return 1;
}

static int update_cpu_power_limits(struct flb_ne *ctx, uint64_t timestamp)
{
    int ret;
    int metric_count;
    int maximum_cpu_count;
    size_t maximum_cpu_count_size;
    IOReturn io_ret;
    CFDictionaryRef status;

    status = NULL;
    io_ret = IOPMCopyCPUPowerStatus(&status);
    if (io_ret == kIOReturnNotFound) {
        flb_plg_debug(ctx->ins, "no CPU power status has been recorded");
        if (status != NULL) {
            CFRelease(status);
        }
        return -1;
    }
    else if (io_ret != kIOReturnSuccess) {
        flb_plg_error(ctx->ins, "failed to read CPU power status: 0x%08x", io_ret);
        if (status != NULL) {
            CFRelease(status);
        }
        return -1;
    }
    else if (status == NULL) {
        flb_plg_error(ctx->ins, "CPU power status is empty");
        return -1;
    }

    metric_count = 0;
    maximum_cpu_count = INT32_MAX;
    maximum_cpu_count_size = sizeof(maximum_cpu_count);
    if (sysctlbyname("hw.logicalcpu_max", &maximum_cpu_count,
                     &maximum_cpu_count_size, NULL, 0) != 0 ||
        maximum_cpu_count < 1) {
        maximum_cpu_count = INT32_MAX;
    }

    ret = set_thermal_metric(
        ctx, &ctx->darwin_thermal_cpu_scheduler_limit, status,
        CFSTR(kIOPMCPUPowerLimitSchedulerTimeKey), "cpu_scheduler_limit_ratio",
        "Represents the percentage (0-100) of CPU time available. 100% at normal "
        "operation. The OS may limit this time for a percentage less than 100%.",
        timestamp, 100.0, 0.0, 100.0);
    if (ret < 0) {
        CFRelease(status);
        return -1;
    }
    metric_count += ret;

    ret = set_thermal_metric(
        ctx, &ctx->darwin_thermal_cpu_available, status,
        CFSTR(kIOPMCPUPowerLimitProcessorCountKey), "cpu_available_cpu",
        "Reflects how many, if any, CPUs have been taken offline. Represented as an "
        "integer number of CPUs (0 - Max CPUs).",
        timestamp, 1.0, 0.0, (double) maximum_cpu_count);
    if (ret < 0) {
        CFRelease(status);
        return -1;
    }
    metric_count += ret;

    ret = set_thermal_metric(
        ctx, &ctx->darwin_thermal_cpu_speed_limit, status,
        CFSTR(kIOPMCPUPowerLimitProcessorSpeedKey), "cpu_speed_limit_ratio",
        "Defines the speed & voltage limits placed on the CPU. Represented as a "
        "percentage (0-100) of maximum CPU speed.",
        timestamp, 100.0, 0.0, 100.0);
    if (ret < 0) {
        CFRelease(status);
        return -1;
    }
    metric_count += ret;

    CFRelease(status);

    if (metric_count == 0) {
        flb_plg_debug(ctx->ins, "CPU power status contains no supported values");
        return -1;
    }

    return 0;
}

#if defined(__arm64__) || defined(__aarch64__)

static int copy_cf_string(CFStringRef source, char *destination, size_t size)
{
    Boolean result;

    if (source == NULL || destination == NULL || size == 0) {
        return -1;
    }

    result = CFStringGetCString(source, destination, size, kCFStringEncodingUTF8);
    if (!result || destination[0] == '\0') {
        return -1;
    }

    return 0;
}

static int update_temperatures(struct flb_ne *ctx, uint64_t timestamp)
{
    int index;
    int name_result;
    int temperature_count;
    int unnamed_sensor_count;
    int32_t page;
    int32_t usage;
    double temperature;
    CFIndex service_count;
    CFTypeRef name_ref;
    CFNumberRef page_number;
    CFNumberRef usage_number;
    CFArrayRef services;
    CFDictionaryRef matching;
    IOHIDEventRef event;
    IOHIDServiceClientRef service;
    IOHIDEventSystemClientRef client;
    const void *keys[2];
    const void *values[2];
    char sensor_name[4096];

    page = 0xff00;
    usage = 5;
    page_number = NULL;
    usage_number = NULL;
    matching = NULL;
    services = NULL;

    client = IOHIDEventSystemClientCreate(kCFAllocatorDefault);
    if (client == NULL) {
        flb_plg_debug(ctx->ins, "failed to create HID event system client");
        return -1;
    }

    page_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &page);
    usage_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &usage);
    if (page_number == NULL || usage_number == NULL) {
        flb_plg_error(ctx->ins, "failed to create HID temperature matching values");
        goto error;
    }

    keys[0] = CFSTR("PrimaryUsagePage");
    keys[1] = CFSTR("PrimaryUsage");
    values[0] = page_number;
    values[1] = usage_number;
    matching = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 2,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    if (matching == NULL) {
        flb_plg_error(ctx->ins, "failed to create HID temperature matching dictionary");
        goto error;
    }

    IOHIDEventSystemClientSetMatching(client, matching);
    services = IOHIDEventSystemClientCopyServices(client);
    if (services == NULL) {
        flb_plg_debug(ctx->ins, "no HID temperature sensor services found");
        goto error;
    }

    service_count = CFArrayGetCount(services);
    temperature_count = 0;
    unnamed_sensor_count = 0;

    for (index = 0; index < service_count; index++) {
        service = (IOHIDServiceClientRef) CFArrayGetValueAtIndex(services, index);
        if (service == NULL) {
            continue;
        }

        name_result = -1;
        name_ref = IOHIDServiceClientCopyProperty(service, CFSTR("Product"));
        if (name_ref != NULL) {
            if (CFGetTypeID(name_ref) == CFStringGetTypeID()) {
                name_result = copy_cf_string((CFStringRef) name_ref,
                                             sensor_name, sizeof(sensor_name));
            }
            CFRelease(name_ref);
        }

        if (name_result != 0) {
            unnamed_sensor_count++;
            snprintf(sensor_name, sizeof(sensor_name),
                     "Unknown #%d", unnamed_sensor_count);
        }

        event = IOHIDServiceClientCopyEvent(service, NE_IOHID_EVENT_TYPE_TEMPERATURE,
                                            0, 0);
        if (event == NULL) {
            continue;
        }

        temperature = IOHIDEventGetFloatValue(
            event, NE_IOHID_EVENT_FIELD_BASE(NE_IOHID_EVENT_TYPE_TEMPERATURE));
        CFRelease(event);

        if (!isfinite(temperature) || temperature < NE_ABSOLUTE_ZERO_CELSIUS) {
            continue;
        }

        cmt_gauge_set(ctx->darwin_thermal_temperature, timestamp, temperature,
                      1, (char *[]) {sensor_name});
        temperature_count++;
    }

    CFRelease(services);
    CFRelease(matching);
    CFRelease(usage_number);
    CFRelease(page_number);
    CFRelease(client);

    if (temperature_count == 0) {
        flb_plg_debug(ctx->ins, "HID temperature services returned no valid readings");
        return -1;
    }

    return 0;

error:
    if (services != NULL) {
        CFRelease(services);
    }
    if (matching != NULL) {
        CFRelease(matching);
    }
    if (usage_number != NULL) {
        CFRelease(usage_number);
    }
    if (page_number != NULL) {
        CFRelease(page_number);
    }
    CFRelease(client);

    return -1;
}

#else

static int update_temperatures(struct flb_ne *ctx, uint64_t timestamp)
{
    (void) ctx;
    (void) timestamp;

    return -1;
}

#endif

static int ne_thermalzone_init(struct flb_ne *ctx)
{
    ctx->darwin_thermal_cpu_scheduler_limit = NULL;
    ctx->darwin_thermal_cpu_available = NULL;
    ctx->darwin_thermal_cpu_speed_limit = NULL;

    ctx->darwin_thermal_temperature = cmt_gauge_create(
        ctx->cmt, "node", "thermal", "temperature_celsius",
        "Temperature of the thermal sensor in Celsius.",
        1, (char *[]) {"sensor"});
    if (ctx->darwin_thermal_temperature == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_thermal_temperature_celsius");
        return -1;
    }

    return 0;
}

static int ne_thermalzone_update(struct flb_input_instance *ins,
                                 struct flb_config *config, void *in_context)
{
    int power_limit_result;
    int temperature_result;
    uint64_t timestamp;
    struct flb_ne *ctx;

    (void) ins;
    (void) config;

    ctx = in_context;
    timestamp = cfl_time_now();

    power_limit_result = update_cpu_power_limits(ctx, timestamp);
    temperature_result = update_temperatures(ctx, timestamp);

    if (power_limit_result != 0 && temperature_result != 0) {
        return -1;
    }

    return 0;
}

struct flb_ne_collector thermalzone_collector = {
    .name = "thermal_zone",
    .cb_init = ne_thermalzone_init,
    .cb_update = ne_thermalzone_update,
    .cb_exit = NULL
};
