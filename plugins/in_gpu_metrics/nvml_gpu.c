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
#include <stdio.h>
#include <string.h>
#include <limits.h>

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

struct nvmlProcessInfo_v1_t {
    unsigned int pid;
    uint64_t usedGpuMemory;
};

struct nvmlProcessInfo_v2_t {
    unsigned int pid;
    uint64_t usedGpuMemory;
    unsigned int gpuInstanceId;
    unsigned int computeInstanceId;
};

struct nvmlProcessInfo_v3_t {
    unsigned int pid;
    uint64_t usedGpuMemory;
    unsigned int gpuInstanceId;
    unsigned int computeInstanceId;
    uint64_t usedGpuCcProtectedMemory;
};

typedef nvmlReturn_t (*nvmlInit_v2_t)(void);
typedef nvmlReturn_t (*nvmlShutdown_t)(void);
typedef nvmlReturn_t (*nvmlDeviceGetCount_v2_t)(unsigned int *device_count);
typedef nvmlReturn_t (*nvmlDeviceGetHandleByIndex_v2_t)(unsigned int index,
                                                         nvmlDevice_t *device);
typedef nvmlReturn_t (*nvmlDeviceGetHandleByUUID_t)(const char *uuid,
                                                     nvmlDevice_t *device);
typedef nvmlReturn_t (*nvmlDeviceGetMemoryInfo_t)(nvmlDevice_t device,
                                                   struct nvmlMemory_t *memory);
typedef nvmlReturn_t (*nvmlDeviceGetUtilizationRates_t)(nvmlDevice_t device,
                                                         struct nvmlUtilization_t *util);
typedef nvmlReturn_t (*nvmlDeviceGetTemperature_t)(nvmlDevice_t device,
                                                    unsigned int sensor_type,
                                                    unsigned int *temp);
typedef nvmlReturn_t (*nvmlDeviceGetPowerUsage_t)(nvmlDevice_t device,
                                                   unsigned int *power);
typedef nvmlReturn_t (*nvmlDeviceGetFanSpeed_t)(nvmlDevice_t device,
                                                 unsigned int *speed);
typedef nvmlReturn_t (*nvmlDeviceGetClockInfo_t)(nvmlDevice_t device,
                                                  unsigned int clock_type,
                                                  unsigned int *clock);
typedef nvmlReturn_t (*nvmlDeviceGetUUID_t)(nvmlDevice_t device,
                                             char *uuid,
                                             unsigned int length);
typedef nvmlReturn_t (*nvmlDeviceGetMigMode_t)(nvmlDevice_t device,
                                                unsigned int *current_mode,
                                                unsigned int *pending_mode);
typedef nvmlReturn_t (*nvmlDeviceGetMaxMigDeviceCount_t)(nvmlDevice_t device,
                                                          unsigned int *count);
typedef nvmlReturn_t (*nvmlDeviceGetMigDeviceHandleByIndex_t)(nvmlDevice_t device,
                                                               unsigned int index,
                                                               nvmlDevice_t *mig_device);
typedef nvmlReturn_t (*nvmlDeviceGetGpuInstanceId_t)(nvmlDevice_t device,
                                                      unsigned int *id);
typedef nvmlReturn_t (*nvmlDeviceGetComputeInstanceId_t)(nvmlDevice_t device,
                                                          unsigned int *id);
typedef nvmlReturn_t (*nvmlDeviceGetDeviceHandleFromMigDeviceHandle_t)(nvmlDevice_t device,
                                                                        nvmlDevice_t *parent);
typedef nvmlReturn_t (*nvmlDeviceGetComputeRunningProcesses_t)(nvmlDevice_t device,
                                                                unsigned int *info_count,
                                                                struct nvmlProcessInfo_v1_t *infos);
typedef nvmlReturn_t (*nvmlDeviceGetGraphicsRunningProcesses_t)(nvmlDevice_t device,
                                                                 unsigned int *info_count,
                                                                 struct nvmlProcessInfo_v1_t *infos);
typedef nvmlReturn_t (*nvmlDeviceGetComputeRunningProcesses_v2_t)(nvmlDevice_t device,
                                                                   unsigned int *info_count,
                                                                   struct nvmlProcessInfo_v2_t *infos);
typedef nvmlReturn_t (*nvmlDeviceGetGraphicsRunningProcesses_v2_t)(nvmlDevice_t device,
                                                                    unsigned int *info_count,
                                                                    struct nvmlProcessInfo_v2_t *infos);
typedef nvmlReturn_t (*nvmlDeviceGetComputeRunningProcesses_v3_t)(nvmlDevice_t device,
                                                                   unsigned int *info_count,
                                                                   struct nvmlProcessInfo_v3_t *infos);
typedef nvmlReturn_t (*nvmlDeviceGetGraphicsRunningProcesses_v3_t)(nvmlDevice_t device,
                                                                    unsigned int *info_count,
                                                                    struct nvmlProcessInfo_v3_t *infos);
typedef const char *(*nvmlErrorString_t)(nvmlReturn_t result);

#define NVML_SUCCESS 0
#define NVML_TEMPERATURE_GPU 0
#define NVML_CLOCK_GRAPHICS 0
#define NVML_CLOCK_SM 1
#define NVML_CLOCK_MEM 2
#define NVML_FEATURE_ENABLED 1
#define NVML_UUID_BUFFER_SIZE 96
#define NVML_MAX_PROCESS_SAMPLES 128
#define NVML_MAX_VALID_PID 4194304

static nvmlInit_v2_t f_nvml_init_v2;
static nvmlShutdown_t f_nvml_shutdown;
static nvmlDeviceGetCount_v2_t f_nvml_device_get_count_v2;
static nvmlDeviceGetHandleByIndex_v2_t f_nvml_device_get_handle_by_index_v2;
static nvmlDeviceGetHandleByUUID_t f_nvml_device_get_handle_by_uuid;
static nvmlDeviceGetMemoryInfo_t f_nvml_device_get_memory_info;
static nvmlDeviceGetUtilizationRates_t f_nvml_device_get_utilization_rates;
static nvmlDeviceGetTemperature_t f_nvml_device_get_temperature;
static nvmlDeviceGetPowerUsage_t f_nvml_device_get_power_usage;
static nvmlDeviceGetFanSpeed_t f_nvml_device_get_fan_speed;
static nvmlDeviceGetClockInfo_t f_nvml_device_get_clock_info;
static nvmlDeviceGetUUID_t f_nvml_device_get_uuid;
static nvmlDeviceGetMigMode_t f_nvml_device_get_mig_mode;
static nvmlDeviceGetMaxMigDeviceCount_t f_nvml_device_get_max_mig_device_count;
static nvmlDeviceGetMigDeviceHandleByIndex_t f_nvml_device_get_mig_device_handle_by_index;
static nvmlDeviceGetGpuInstanceId_t f_nvml_device_get_gpu_instance_id;
static nvmlDeviceGetComputeInstanceId_t f_nvml_device_get_compute_instance_id;
static nvmlDeviceGetDeviceHandleFromMigDeviceHandle_t f_nvml_device_get_parent_from_mig;
static nvmlDeviceGetComputeRunningProcesses_t f_nvml_device_get_compute_running_processes;
static nvmlDeviceGetGraphicsRunningProcesses_t f_nvml_device_get_graphics_running_processes;
static nvmlDeviceGetComputeRunningProcesses_v2_t f_nvml_device_get_compute_running_processes_v2;
static nvmlDeviceGetGraphicsRunningProcesses_v2_t f_nvml_device_get_graphics_running_processes_v2;
static nvmlDeviceGetComputeRunningProcesses_v3_t f_nvml_device_get_compute_running_processes_v3;
static nvmlDeviceGetGraphicsRunningProcesses_v3_t f_nvml_device_get_graphics_running_processes_v3;
static nvmlErrorString_t f_nvml_error_string;

static void nvml_reset_api_symbols()
{
    f_nvml_init_v2 = NULL;
    f_nvml_shutdown = NULL;
    f_nvml_device_get_count_v2 = NULL;
    f_nvml_device_get_handle_by_index_v2 = NULL;
    f_nvml_device_get_handle_by_uuid = NULL;
    f_nvml_device_get_memory_info = NULL;
    f_nvml_device_get_utilization_rates = NULL;
    f_nvml_device_get_temperature = NULL;
    f_nvml_device_get_power_usage = NULL;
    f_nvml_device_get_fan_speed = NULL;
    f_nvml_device_get_clock_info = NULL;
    f_nvml_device_get_uuid = NULL;
    f_nvml_device_get_mig_mode = NULL;
    f_nvml_device_get_max_mig_device_count = NULL;
    f_nvml_device_get_mig_device_handle_by_index = NULL;
    f_nvml_device_get_gpu_instance_id = NULL;
    f_nvml_device_get_compute_instance_id = NULL;
    f_nvml_device_get_parent_from_mig = NULL;
    f_nvml_device_get_compute_running_processes = NULL;
    f_nvml_device_get_graphics_running_processes = NULL;
    f_nvml_device_get_compute_running_processes_v2 = NULL;
    f_nvml_device_get_graphics_running_processes_v2 = NULL;
    f_nvml_device_get_compute_running_processes_v3 = NULL;
    f_nvml_device_get_graphics_running_processes_v3 = NULL;
    f_nvml_error_string = NULL;
}

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

static void load_optional_nvml_symbol(struct in_gpu_metrics *ctx, const char *name, void **target)
{
    *target = dlsym(ctx->nvml_lib_handle, name);
    if (*target == NULL) {
        flb_plg_debug(ctx->ins, "optional NVML symbol '%s' is unavailable", name);
    }
}

static int nvml_read_device_uuid(nvmlDevice_t device, char *buf, size_t size)
{
    nvmlReturn_t result;

    if (f_nvml_device_get_uuid == NULL) {
        return -1;
    }

    result = f_nvml_device_get_uuid(device, buf, (unsigned int) size);
    if (result != NVML_SUCCESS) {
        return -1;
    }

    return 0;
}

static int nvml_register_card(struct in_gpu_metrics *ctx,
                              int card_id,
                              int gpu_instance_id,
                              int compute_instance_id,
                              const char *uuid,
                              const char *parent_uuid)
{
    struct gpu_card *card;

    card = flb_calloc(1, sizeof(struct gpu_card));
    if (card == NULL) {
        flb_errno();
        return -1;
    }

    card->id = card_id;
    card->backend_type = GPU_BACKEND_NVML;
    card->gpu_instance_id = gpu_instance_id;
    card->compute_instance_id = compute_instance_id;

    if (uuid != NULL) {
        card->uuid = flb_sds_create(uuid);
        if (card->uuid == NULL) {
            flb_free(card);
            return -1;
        }
    }

    if (parent_uuid != NULL) {
        card->parent_uuid = flb_sds_create(parent_uuid);
        if (card->parent_uuid == NULL) {
            if (card->uuid != NULL) {
                flb_sds_destroy(card->uuid);
            }
            flb_free(card);
            return -1;
        }
    }

    cfl_list_add(&card->_head, &ctx->cards);
    return 0;
}

static int nvml_detect_mig_devices(struct in_gpu_metrics *ctx,
                                   int parent_card_id,
                                   nvmlDevice_t parent_device,
                                   const char *parent_uuid)
{
    nvmlDevice_t mig_device;
    nvmlDevice_t mig_parent;
    unsigned int current_mode;
    unsigned int pending_mode;
    unsigned int mig_count;
    unsigned int mig_index;
    unsigned int gi;
    unsigned int ci;
    char mig_uuid[NVML_UUID_BUFFER_SIZE];
    char resolved_parent_uuid[NVML_UUID_BUFFER_SIZE];
    const char *final_parent_uuid;
    nvmlReturn_t result;

    if (f_nvml_device_get_mig_mode == NULL ||
        f_nvml_device_get_max_mig_device_count == NULL ||
        f_nvml_device_get_mig_device_handle_by_index == NULL ||
        f_nvml_device_get_gpu_instance_id == NULL ||
        f_nvml_device_get_compute_instance_id == NULL) {
        return 0;
    }

    result = f_nvml_device_get_mig_mode(parent_device, &current_mode, &pending_mode);
    if (result != NVML_SUCCESS || current_mode != NVML_FEATURE_ENABLED) {
        return 0;
    }

    result = f_nvml_device_get_max_mig_device_count(parent_device, &mig_count);
    if (result != NVML_SUCCESS) {
        return -1;
    }

    for (mig_index = 0; mig_index < mig_count; mig_index++) {
        result = f_nvml_device_get_mig_device_handle_by_index(parent_device, mig_index, &mig_device);
        if (result != NVML_SUCCESS) {
            continue;
        }

        if (nvml_read_device_uuid(mig_device, mig_uuid, sizeof(mig_uuid)) != 0) {
            continue;
        }

        result = f_nvml_device_get_gpu_instance_id(mig_device, &gi);
        if (result != NVML_SUCCESS) {
            continue;
        }

        result = f_nvml_device_get_compute_instance_id(mig_device, &ci);
        if (result != NVML_SUCCESS) {
            continue;
        }

        final_parent_uuid = parent_uuid;
        if (final_parent_uuid == NULL && f_nvml_device_get_parent_from_mig != NULL) {
            result = f_nvml_device_get_parent_from_mig(mig_device, &mig_parent);
            if (result == NVML_SUCCESS &&
                nvml_read_device_uuid(mig_parent, resolved_parent_uuid, sizeof(resolved_parent_uuid)) == 0) {
                final_parent_uuid = resolved_parent_uuid;
            }
        }

        if (nvml_register_card(ctx,
                               parent_card_id,
                               (int) gi,
                               (int) ci,
                               mig_uuid,
                               final_parent_uuid) != 0) {
            return -1;
        }
    }

    return 0;
}

static int nvml_get_device_handle(struct gpu_card *card, nvmlDevice_t *device)
{
    nvmlReturn_t result;

    if (card->uuid != NULL && f_nvml_device_get_handle_by_uuid != NULL) {
        result = f_nvml_device_get_handle_by_uuid(card->uuid, device);
        if (result == NVML_SUCCESS) {
            return 0;
        }
    }

    result = f_nvml_device_get_handle_by_index_v2((unsigned int) card->id, device);
    if (result != NVML_SUCCESS) {
        return -1;
    }

    return 0;
}

static int nvml_process_entry_is_valid(unsigned int pid, uint64_t used_gpu_memory)
{
    if (pid == 0 || pid == UINT_MAX) {
        return FLB_FALSE;
    }

    /*
     * Linux PID upper bound is 2^22. This avoids emitting invalid IDs that
     * may appear when some NVML process entries are partially populated.
     */
    if (pid > NVML_MAX_VALID_PID) {
        return FLB_FALSE;
    }

    if (used_gpu_memory == UINT64_MAX) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static void nvml_emit_process_memory_samples_v1(struct in_gpu_metrics *ctx,
                                                const char *card_label,
                                                nvmlDevice_t device,
                                                uint64_t ts,
                                                nvmlDeviceGetComputeRunningProcesses_t api)
{
    struct nvmlProcessInfo_v1_t infos[NVML_MAX_PROCESS_SAMPLES];
    unsigned int info_count;
    unsigned int i;
    char pid_buf[32];
    nvmlReturn_t result;

    if (api == NULL || ctx->g_process_memory == NULL) {
        return;
    }

    info_count = NVML_MAX_PROCESS_SAMPLES;
    result = api(device, &info_count, infos);
    if (result != NVML_SUCCESS) {
        return;
    }

    for (i = 0; i < info_count; i++) {
        if (nvml_process_entry_is_valid(infos[i].pid,
                                        infos[i].usedGpuMemory) == FLB_FALSE) {
            continue;
        }
        snprintf(pid_buf, sizeof(pid_buf), "%u", infos[i].pid);
        cmt_gauge_set(ctx->g_process_memory, ts, (double) infos[i].usedGpuMemory, 3,
                      (char *[]) { (char *) card_label, "nvidia", pid_buf});
    }
}

static void nvml_emit_process_memory_samples_v2(struct in_gpu_metrics *ctx,
                                                const char *card_label,
                                                nvmlDevice_t device,
                                                uint64_t ts,
                                                nvmlDeviceGetComputeRunningProcesses_v2_t api)
{
    struct nvmlProcessInfo_v2_t infos[NVML_MAX_PROCESS_SAMPLES];
    unsigned int info_count;
    unsigned int i;
    char pid_buf[32];
    nvmlReturn_t result;

    if (api == NULL || ctx->g_process_memory == NULL) {
        return;
    }

    info_count = NVML_MAX_PROCESS_SAMPLES;
    result = api(device, &info_count, infos);
    if (result != NVML_SUCCESS) {
        return;
    }

    for (i = 0; i < info_count; i++) {
        if (nvml_process_entry_is_valid(infos[i].pid,
                                        infos[i].usedGpuMemory) == FLB_FALSE) {
            continue;
        }
        snprintf(pid_buf, sizeof(pid_buf), "%u", infos[i].pid);
        cmt_gauge_set(ctx->g_process_memory, ts, (double) infos[i].usedGpuMemory, 3,
                      (char *[]) { (char *) card_label, "nvidia", pid_buf});
    }
}

static void nvml_emit_process_memory_samples_v3(struct in_gpu_metrics *ctx,
                                                const char *card_label,
                                                nvmlDevice_t device,
                                                uint64_t ts,
                                                nvmlDeviceGetComputeRunningProcesses_v3_t api)
{
    struct nvmlProcessInfo_v3_t infos[NVML_MAX_PROCESS_SAMPLES];
    unsigned int info_count;
    unsigned int i;
    char pid_buf[32];
    nvmlReturn_t result;

    if (api == NULL || ctx->g_process_memory == NULL) {
        return;
    }

    info_count = NVML_MAX_PROCESS_SAMPLES;
    result = api(device, &info_count, infos);
    if (result != NVML_SUCCESS) {
        return;
    }

    for (i = 0; i < info_count; i++) {
        if (nvml_process_entry_is_valid(infos[i].pid,
                                        infos[i].usedGpuMemory) == FLB_FALSE) {
            continue;
        }
        snprintf(pid_buf, sizeof(pid_buf), "%u", infos[i].pid);
        cmt_gauge_set(ctx->g_process_memory, ts, (double) infos[i].usedGpuMemory, 3,
                      (char *[]) { (char *) card_label, "nvidia", pid_buf});
    }
}

static void nvml_collect_process_memory(struct in_gpu_metrics *ctx,
                                        struct gpu_card *card,
                                        nvmlDevice_t device,
                                        uint64_t ts,
                                        const char *card_label)
{
    if (f_nvml_device_get_compute_running_processes_v3 != NULL) {
        nvml_emit_process_memory_samples_v3(ctx, card_label, device, ts,
                                            f_nvml_device_get_compute_running_processes_v3);
    }
    if (f_nvml_device_get_compute_running_processes_v2 != NULL) {
        nvml_emit_process_memory_samples_v2(ctx, card_label, device, ts,
                                            f_nvml_device_get_compute_running_processes_v2);
    }
    if (f_nvml_device_get_compute_running_processes != NULL) {
        nvml_emit_process_memory_samples_v1(ctx, card_label, device, ts,
                                            f_nvml_device_get_compute_running_processes);
    }

    if (f_nvml_device_get_graphics_running_processes_v3 != NULL) {
        nvml_emit_process_memory_samples_v3(ctx, card_label, device, ts,
                                            f_nvml_device_get_graphics_running_processes_v3);
    }
    if (f_nvml_device_get_graphics_running_processes_v2 != NULL) {
        nvml_emit_process_memory_samples_v2(ctx, card_label, device, ts,
                                            f_nvml_device_get_graphics_running_processes_v2);
    }
    if (f_nvml_device_get_graphics_running_processes != NULL) {
        nvml_emit_process_memory_samples_v1(ctx, card_label, device, ts,
                                            f_nvml_device_get_graphics_running_processes);
    }

    if (ctx->g_mig_info != NULL &&
        card->gpu_instance_id >= 0 &&
        card->compute_instance_id >= 0 &&
        card->parent_uuid != NULL) {
        char gi_buf[16];
        char ci_buf[16];

        snprintf(gi_buf, sizeof(gi_buf), "%d", card->gpu_instance_id);
        snprintf(ci_buf, sizeof(ci_buf), "%d", card->compute_instance_id);

        cmt_gauge_set(ctx->g_mig_info, ts, 1.0, 5,
                      (char *[]) { (char *) card_label, "nvidia", card->parent_uuid,
                                   gi_buf, ci_buf});
    }
}

int nvml_gpu_initialize(struct in_gpu_metrics *ctx)
{
    nvmlReturn_t result;

    nvml_reset_api_symbols();

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
        nvml_reset_api_symbols();
        return -1;
    }

    f_nvml_error_string = dlsym(ctx->nvml_lib_handle, "nvmlErrorString");
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetFanSpeed", (void **) &f_nvml_device_get_fan_speed);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetClockInfo", (void **) &f_nvml_device_get_clock_info);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetUUID", (void **) &f_nvml_device_get_uuid);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetHandleByUUID", (void **) &f_nvml_device_get_handle_by_uuid);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetMigMode", (void **) &f_nvml_device_get_mig_mode);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetMaxMigDeviceCount",
                              (void **) &f_nvml_device_get_max_mig_device_count);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetMigDeviceHandleByIndex",
                              (void **) &f_nvml_device_get_mig_device_handle_by_index);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetGpuInstanceId", (void **) &f_nvml_device_get_gpu_instance_id);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetComputeInstanceId",
                              (void **) &f_nvml_device_get_compute_instance_id);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetDeviceHandleFromMigDeviceHandle",
                              (void **) &f_nvml_device_get_parent_from_mig);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetComputeRunningProcesses_v3",
                              (void **) &f_nvml_device_get_compute_running_processes_v3);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetGraphicsRunningProcesses_v3",
                              (void **) &f_nvml_device_get_graphics_running_processes_v3);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetComputeRunningProcesses_v2",
                              (void **) &f_nvml_device_get_compute_running_processes_v2);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetGraphicsRunningProcesses_v2",
                              (void **) &f_nvml_device_get_graphics_running_processes_v2);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetComputeRunningProcesses",
                              (void **) &f_nvml_device_get_compute_running_processes);
    load_optional_nvml_symbol(ctx, "nvmlDeviceGetGraphicsRunningProcesses",
                              (void **) &f_nvml_device_get_graphics_running_processes);

    result = f_nvml_init_v2();
    if (result != NVML_SUCCESS) {
        flb_plg_warn(ctx->ins, "NVML init failed: %s", nvml_result_to_string(result));
        dlclose(ctx->nvml_lib_handle);
        ctx->nvml_lib_handle = NULL;
        nvml_reset_api_symbols();
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
    nvmlDevice_t device;
    nvmlReturn_t result;
    int uuid_ok;
    char uuid[NVML_UUID_BUFFER_SIZE];
    int detected;

    if (ctx->nvml_initialized == FLB_FALSE) {
        return 0;
    }

    result = f_nvml_device_get_count_v2(&count);
    if (result != NVML_SUCCESS) {
        flb_plg_warn(ctx->ins, "NVML device count failed: %s", nvml_result_to_string(result));
        return -1;
    }

    detected = 0;

    for (index = 0; index < count; index++) {
        if (!gpu_should_include_card(ctx, (int) index)) {
            continue;
        }

        result = f_nvml_device_get_handle_by_index_v2(index, &device);
        if (result != NVML_SUCCESS) {
            continue;
        }

        uuid_ok = (nvml_read_device_uuid(device, uuid, sizeof(uuid)) == 0);

        if (uuid_ok) {
            if (nvml_register_card(ctx, (int) index, -1, -1, uuid, NULL) != 0) {
                return -1;
            }
        }
        else {
            if (nvml_register_card(ctx, (int) index, -1, -1, NULL, NULL) != 0) {
                return -1;
            }
        }
        detected++;

        if (nvml_detect_mig_devices(ctx, (int) index, device,
                                    uuid_ok ? uuid : NULL) != 0) {
            flb_plg_warn(ctx->ins, "failed to detect MIG devices for card%d", (int) index);
        }
    }

    if (detected > 0) {
        flb_plg_info(ctx->ins, "detected %d NVIDIA GPU card(s) via NVML", detected);
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
    unsigned int sm_clock_mhz;
    unsigned int mem_clock_mhz;
    unsigned int graphics_clock_mhz;
    nvmlReturn_t result;
    uint64_t ts;
    flb_sds_t fallback_card_id;
    const char *card_label;

    if (ctx->nvml_initialized == FLB_FALSE) {
        return -1;
    }

    if (nvml_get_device_handle(card, &device) != 0) {
        return -1;
    }

    fallback_card_id = NULL;
    card_label = card->uuid;

    if (card_label == NULL) {
        fallback_card_id = flb_sds_create_size(16);
        if (fallback_card_id == NULL) {
            flb_errno();
            return -1;
        }
        fallback_card_id = flb_sds_printf(&fallback_card_id, "%d", card->id);
        if (fallback_card_id == NULL) {
            return -1;
        }
        card_label = fallback_card_id;
    }

    ts = cfl_time_now();

    result = f_nvml_device_get_utilization_rates(device, &util);
    if (result == NVML_SUCCESS) {
        cmt_gauge_set(ctx->g_utilization, ts, (double) util.gpu, 2,
                      (char *[]) {(char *) card_label, "nvidia"});
    }

    result = f_nvml_device_get_memory_info(device, &memory);
    if (result == NVML_SUCCESS) {
        cmt_gauge_set(ctx->g_mem_used, ts, (double) memory.used, 2,
                      (char *[]) {(char *) card_label, "nvidia"});
        cmt_gauge_set(ctx->g_mem_total, ts, (double) memory.total, 2,
                      (char *[]) {(char *) card_label, "nvidia"});
    }

    if (f_nvml_device_get_clock_info != NULL) {
        result = f_nvml_device_get_clock_info(device, NVML_CLOCK_SM, &sm_clock_mhz);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_clock, ts, (double) sm_clock_mhz, 3,
                          (char *[]) {(char *) card_label, "nvidia", "sm"});
        }

        result = f_nvml_device_get_clock_info(device, NVML_CLOCK_MEM, &mem_clock_mhz);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_clock, ts, (double) mem_clock_mhz, 3,
                          (char *[]) {(char *) card_label, "nvidia", "memory"});
        }

        result = f_nvml_device_get_clock_info(device, NVML_CLOCK_GRAPHICS, &graphics_clock_mhz);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_clock, ts, (double) graphics_clock_mhz, 3,
                          (char *[]) {(char *) card_label, "nvidia", "graphics"});
        }
    }

    if (ctx->enable_temperature) {
        result = f_nvml_device_get_temperature(device, NVML_TEMPERATURE_GPU, &temp);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_temp, ts, (double) temp, 2,
                          (char *[]) {(char *) card_label, "nvidia"});
        }
    }

    if (ctx->enable_power) {
        result = f_nvml_device_get_power_usage(device, &power_mw);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_power, ts, (double) power_mw / 1000.0, 2,
                          (char *[]) {(char *) card_label, "nvidia"});
        }
    }

    if (f_nvml_device_get_fan_speed != NULL) {
        result = f_nvml_device_get_fan_speed(device, &fan_percent);
        if (result == NVML_SUCCESS) {
            cmt_gauge_set(ctx->g_fan_pwm, ts, (double) fan_percent, 2,
                          (char *[]) {(char *) card_label, "nvidia"});
        }
    }

    nvml_collect_process_memory(ctx, card, device, ts, card_label);

    if (fallback_card_id != NULL) {
        flb_sds_destroy(fallback_card_id);
    }

    return 0;
}

void nvml_gpu_shutdown(struct in_gpu_metrics *ctx)
{
    if (ctx->nvml_initialized == FLB_TRUE) {
        if (f_nvml_shutdown != NULL) {
            f_nvml_shutdown();
        }
        ctx->nvml_initialized = FLB_FALSE;
    }

    if (ctx->nvml_lib_handle != NULL) {
        dlclose(ctx->nvml_lib_handle);
        ctx->nvml_lib_handle = NULL;
    }

    nvml_reset_api_symbols();
}
