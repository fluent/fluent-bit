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

#include <dlfcn.h>
#include <stdint.h>

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <cfl/cfl_time.h>

#include "nvml_gpu.h"

typedef int nvmlReturn_t;
typedef void *nvmlDevice_t;

struct nvmlMemory_t {
    uint64_t total;
    uint64_t free;
    uint64_t used;
};

struct nvmlUtilization_t {
    unsigned int gpu;
    unsigned int memory;
};

typedef nvmlReturn_t (*nvmlInit_v2_t)(void);
typedef nvmlReturn_t (*nvmlShutdown_t)(void);
typedef nvmlReturn_t (*nvmlDeviceGetCount_v2_t)(unsigned int *device_count);
typedef nvmlReturn_t (*nvmlDeviceGetHandleByIndex_v2_t)(unsigned int index, nvmlDevice_t *device);
typedef nvmlReturn_t (*nvmlDeviceGetMemoryInfo_t)(nvmlDevice_t device, struct nvmlMemory_t *memory);
typedef nvmlReturn_t (*nvmlDeviceGetUtilizationRates_t)(nvmlDevice_t device, struct nvmlUtilization_t *util);
typedef nvmlReturn_t (*nvmlDeviceGetTemperature_t)(nvmlDevice_t device,
                                                    unsigned int sensor_type,
                                                    unsigned int *temp);
typedef nvmlReturn_t (*nvmlDeviceGetPowerUsage_t)(nvmlDevice_t device, unsigned int *power);
typedef nvmlReturn_t (*nvmlDeviceGetFanSpeed_t)(nvmlDevice_t device, unsigned int *speed);
typedef const char *(*nvmlErrorString_t)(nvmlReturn_t result);

#define NVML_SUCCESS 0
#define NVML_TEMPERATURE_GPU 0

static nvmlInit_v2_t f_nvml_init_v2;
static nvmlShutdown_t f_nvml_shutdown;
static nvmlDeviceGetCount_v2_t f_nvml_device_get_count_v2;
static nvmlDeviceGetHandleByIndex_v2_t f_nvml_device_get_handle_by_index_v2;
static nvmlDeviceGetMemoryInfo_t f_nvml_device_get_memory_info;
static nvmlDeviceGetUtilizationRates_t f_nvml_device_get_utilization_rates;
static nvmlDeviceGetTemperature_t f_nvml_device_get_temperature;
static nvmlDeviceGetPowerUsage_t f_nvml_device_get_power_usage;
static nvmlDeviceGetFanSpeed_t f_nvml_device_get_fan_speed;
static nvmlErrorString_t f_nvml_error_string;

static const char *nvml_result_to_string(nvmlReturn_t result)
{
    if (f_nvml_error_string != NULL) {
        return f_nvml_error_string(result);
    }
    return "unknown";
}

static int load_nvml_symbol(struct in_gpu_metrics *ctx, const char *name, void **target)
{
    *target = dlsym(ctx->nvml_lib_handle, name);
    if (*target == NULL) {
        flb_plg_warn(ctx->ins, "NVML symbol '%s' is missing", name);
        return -1;
    }

    return 0;
}

int nvml_gpu_initialize(struct in_gpu_metrics *ctx)
{
    nvmlReturn_t result;

    if (ctx->enable_nvml == FLB_FALSE) {
        return 0;
    }

    ctx->nvml_lib_handle = dlopen("libnvidia-ml.so.1", RTLD_LAZY);
    if (ctx->nvml_lib_handle == NULL) {
        ctx->nvml_lib_handle = dlopen("libnvidia-ml.so", RTLD_LAZY);
    }
    if (ctx->nvml_lib_handle == NULL) {
        flb_plg_info(ctx->ins,
                     "NVML shared library not found; NVIDIA GPU metrics are disabled");
        return 0;
    }

    if (load_nvml_symbol(ctx, "nvmlInit_v2", (void **) &f_nvml_init_v2) != 0 ||
        load_nvml_symbol(ctx, "nvmlShutdown", (void **) &f_nvml_shutdown) != 0 ||
        load_nvml_symbol(ctx, "nvmlDeviceGetCount_v2", (void **) &f_nvml_device_get_count_v2) != 0 ||
        load_nvml_symbol(ctx, "nvmlDeviceGetHandleByIndex_v2",
                         (void **) &f_nvml_device_get_handle_by_index_v2) != 0 ||
        load_nvml_symbol(ctx, "nvmlDeviceGetMemoryInfo", (void **) &f_nvml_device_get_memory_info) != 0 ||
        load_nvml_symbol(ctx, "nvmlDeviceGetUtilizationRates",
                         (void **) &f_nvml_device_get_utilization_rates) != 0 ||
        load_nvml_symbol(ctx, "nvmlDeviceGetTemperature",
                         (void **) &f_nvml_device_get_temperature) != 0 ||
        load_nvml_symbol(ctx, "nvmlDeviceGetPowerUsage", (void **) &f_nvml_device_get_power_usage) != 0) {
        dlclose(ctx->nvml_lib_handle);
        ctx->nvml_lib_handle = NULL;
        return -1;
    }

    f_nvml_error_string = dlsym(ctx->nvml_lib_handle, "nvmlErrorString");
    f_nvml_device_get_fan_speed = dlsym(ctx->nvml_lib_handle, "nvmlDeviceGetFanSpeed");

    result = f_nvml_init_v2();
    if (result != NVML_SUCCESS) {
        flb_plg_warn(ctx->ins, "NVML init failed: %s", nvml_result_to_string(result));
        dlclose(ctx->nvml_lib_handle);
        ctx->nvml_lib_handle = NULL;
        return -1;
    }

    ctx->nvml_initialized = FLB_TRUE;
    flb_plg_info(ctx->ins, "NVML backend enabled");
    return 0;
}

int nvml_gpu_detect_cards(struct in_gpu_metrics *ctx)
{
    unsigned int index;
    unsigned int count;
    struct gpu_card *card;
    nvmlReturn_t result;

    if (ctx->nvml_initialized == FLB_FALSE) {
        return 0;
    }

    result = f_nvml_device_get_count_v2(&count);
    if (result != NVML_SUCCESS) {
        flb_plg_warn(ctx->ins, "NVML device count failed: %s", nvml_result_to_string(result));
        return -1;
    }

    for (index = 0; index < count; index++) {
        card = flb_calloc(1, sizeof(struct gpu_card));
        if (card == NULL) {
            flb_errno();
            return -1;
        }

        card->id = (int) index;
        card->backend_type = GPU_BACKEND_NVML;
        cfl_list_add(&card->_head, &ctx->cards);
    }

    if (count > 0) {
        flb_plg_info(ctx->ins, "detected %u NVIDIA GPU(s) via NVML", count);
    }

    return 0;
}

int nvml_gpu_collect_metrics(struct in_gpu_metrics *ctx, struct gpu_card *card)
{
    nvmlDevice_t device;
    struct nvmlMemory_t memory;
    struct nvmlUtilization_t util;
    unsigned int temp;
    unsigned int power_mw;
    unsigned int fan_percent;
    nvmlReturn_t result;
    uint64_t ts;
    flb_sds_t card_id;

    if (ctx->nvml_initialized == FLB_FALSE) {
        return -1;
    }

    result = f_nvml_device_get_handle_by_index_v2((unsigned int) card->id, &device);
    if (result != NVML_SUCCESS) {
        flb_plg_debug(ctx->ins, "NVML handle lookup failed for card%d: %s",
                      card->id, nvml_result_to_string(result));
        return -1;
    }

    card_id = flb_sds_create_size(16);
    if (card_id == NULL) {
        flb_errno();
        return -1;
    }
    card_id = flb_sds_printf(&card_id, "%d", card->id);
    if (card_id == NULL) {
        return -1;
    }

    ts = cfl_time_now();

    result = f_nvml_device_get_utilization_rates(device, &util);
    if (result == NVML_SUCCESS) {
        cmt_gauge_set(ctx->g_utilization, ts, (double) util.gpu, 2,
                      (char *[]) {card_id, "nvidia"});
    }

    result = f_nvml_device_get_memory_info(device, &memory);
    if (result == NVML_SUCCESS) {
        cmt_gauge_set(ctx->g_mem_used, ts, (double) memory.used, 2,
                      (char *[]) {card_id, "nvidia"});
        cmt_gauge_set(ctx->g_mem_total, ts, (double) memory.total, 2,
                      (char *[]) {card_id, "nvidia"});
    }

    if (ctx->enable_temperature) {
        result = f_nvml_device_get_temperature(device, NVML_TEMPERATURE_GPU, &temp);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_temp, ts, (double) temp, 2,
                          (char *[]) {card_id, "nvidia"});
        }
    }

    if (ctx->enable_power) {
        result = f_nvml_device_get_power_usage(device, &power_mw);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_power, ts, (double) power_mw / 1000.0, 2,
                          (char *[]) {card_id, "nvidia"});
        }
    }

    if (f_nvml_device_get_fan_speed != NULL) {
        result = f_nvml_device_get_fan_speed(device, &fan_percent);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_fan_pwm, ts, (double) fan_percent, 2,
                          (char *[]) {card_id, "nvidia"});
        }
    }

    flb_sds_destroy(card_id);
    return 0;
}

void nvml_gpu_shutdown(struct in_gpu_metrics *ctx)
{
    if (ctx->nvml_initialized == FLB_TRUE) {
        f_nvml_shutdown();
        ctx->nvml_initialized = FLB_FALSE;
    }
    if (ctx->nvml_lib_handle != NULL) {
        dlclose(ctx->nvml_lib_handle);
        ctx->nvml_lib_handle = NULL;
    }
}
