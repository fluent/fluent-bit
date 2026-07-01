/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022-2025 The Fluent Bit Authors
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

#include <windows.h>

#include "we.h"
#include "we_logical_disk.h"
#include "we_util.h"
#include "we_metric.h"
#include "we_perflib.h"


struct we_perflib_metric_source logical_disk_metric_sources[] = {
        WE_PERFLIB_METRIC_SOURCE("requests_queued",
                                 "Current Disk Queue Length",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_bytes_total",
                                 "Disk Read Bytes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_total",
                                 "Disk Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_bytes_total",
                                 "Disk Write Bytes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_total",
                                 "Disk Writes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_seconds_total",
                                 "% Disk Read Time",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_seconds_total",
                                 "% Disk Write Time",
                                 NULL),

        /* 'free_bytes' and 'size_bytes' are now collected via Windows API */

        WE_PERFLIB_METRIC_SOURCE("idle_seconds_total",
                                 "% Idle Time",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("split_ios_total",
                                 "Split IO/Sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_latency_seconds_total",
                                 "Avg. Disk sec/Read",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_latency_seconds_total",
                                 "Avg. Disk sec/Write",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_write_latency_seconds_total",
                                 "Avg. Disk sec/Transfer",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("avg_read_requests_queued",
                                 "Avg. Disk Read Queue Length",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("avg_write_requests_queued",
                                 "Avg. Disk Write Queue Length",
                                 NULL),

        WE_PERFLIB_TERMINATOR_SOURCE()
    };

struct we_perflib_metric_spec logical_disk_metric_specs[] = {
        WE_PERFLIB_GAUGE_SPEC("requests_queued",
                              "Number of queued requests on the disk",
                              "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_bytes_total",
                                "Number of read bytes from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_total",
                                "Number of read from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_bytes_total",
                                "Number of write bytes to the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_total",
                                "Number of write from to disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_seconds_total",
                                "Total amount of reading time from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_seconds_total",
                                "Total amount of writeing time to the disk",
                                "volume"),

        /* 'free_bytes' and 'size_bytes' are now collected via Windows API */

        WE_PERFLIB_COUNTER_SPEC("idle_seconds_total",
                                "Total amount of idling time on the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("split_ios_total",
                                "Total amount of split I/O operations on the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_latency_seconds_total",
                                "Average latency, in seconds, to read from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_latency_seconds_total",
                                "Average latency, in seconds, to write into the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_write_latency_seconds_total",
                                "Average latency, in seconds, to transfer operations on the disk",
                                "volume"),

        WE_PERFLIB_GAUGE_SPEC("avg_read_requests_queued",
                              "Average number of read requests that were queued for the selected disk during the sample interval",
                              "volume"),

        WE_PERFLIB_GAUGE_SPEC("avg_write_requests_queued",
                              "Average number of write requests that were queued for the selected disk during the sample interval",
                              "volume"),

        WE_PERFLIB_TERMINATOR_SPEC()
    };


int we_logical_disk_init(struct flb_we *ctx)
{
    struct we_perflib_metric_source *metric_sources;
    int                              result;
    struct cmt_gauge                *g;

    ctx->logical_disk.operational = FLB_FALSE;

    /* Create gauges for metrics collected via Windows API */
    g = cmt_gauge_create(ctx->cmt, "windows", "logical_disk", "size_bytes",
                         "Total size of the disk in bytes",
                         1, (char *[]) {"volume"});
    if (!g) {
        return -1;
    }
    ctx->logical_disk.size_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "logical_disk", "free_bytes",
                         "Free space on the disk in bytes",
                         1, (char *[]) {"volume"});
    if (!g) {
        return -1;
    }
    ctx->logical_disk.free_bytes = g;

    ctx->logical_disk.metrics = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 32, 128);

    if (ctx->logical_disk.metrics == NULL) {
        flb_plg_error(ctx->ins, "could not create metrics hash table for logical_disk metrics");

        return -1;
    }

    result = we_initialize_perflib_metric_specs(ctx->cmt,
                                                ctx->logical_disk.metrics,
                                                "windows",
                                                "logical_disk",
                                                &ctx->logical_disk.metric_specs,
                                                logical_disk_metric_specs);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize logical_disk metric specs");

        return -2;
    }

    ctx->logical_disk.query = (char *) "LogicalDisk";

    result = we_initialize_perflib_metric_sources(ctx->logical_disk.metrics,
                                                  &ctx->logical_disk.metric_sources,
                                                  logical_disk_metric_sources);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize logical_disk metric sources");

        we_deinitialize_perflib_metric_specs(ctx->logical_disk.metric_specs);
        flb_free(ctx->logical_disk.metric_specs);

        return -3;
    }

    ctx->logical_disk.operational = FLB_TRUE;

    return 0;
}

int we_logical_disk_exit(struct flb_we *ctx)
{
    if (ctx->logical_disk.operational) {
        we_deinitialize_perflib_metric_sources(ctx->logical_disk.metric_sources);
        we_deinitialize_perflib_metric_specs(ctx->logical_disk.metric_specs);

        flb_free(ctx->logical_disk.metric_sources);
        flb_free(ctx->logical_disk.metric_specs);
    }

    ctx->logical_disk.operational = FLB_FALSE;

    return 0;
}

static int logical_disk_regex_match(struct flb_regex *regex, char *instance_name)
{
    if (regex == NULL) {
        return 0;
    }
    return flb_regex_match(regex, (unsigned char *)instance_name, strlen(instance_name));
}


int we_logical_disk_instance_hook(char *instance_name, struct flb_we *ctx)
{
    if (strcasecmp(instance_name, "_Total") == 0) {
        return 1;
    }

    if (logical_disk_regex_match(ctx->denying_disk_regex, instance_name) ||
        !logical_disk_regex_match(ctx->allowing_disk_regex, instance_name)) {
        return 1;
    }

    return 0;
}

int we_logical_disk_label_prepend_hook(char                           **label_list,
                                       size_t                           label_list_size,
                                       size_t                          *label_count,
                                       struct we_perflib_metric_source *metric_source,
                                       char                            *instance_name,
                                       struct we_perflib_counter       *counter)
{
    if (label_count == NULL) {
        return -1;
    }

    if (*label_count >= label_list_size) {
        return -2;
    }

    label_list[(*label_count)++] = instance_name;

    return 0;
}

static BOOL we_get_volume_perflib_instance_name(LPCWSTR volume_guid_path, LPWSTR out_buffer, DWORD out_buffer_size)
{
    wchar_t device_name[MAX_PATH] = {0};
    wchar_t dos_drive[3] = L" :";
    DWORD i;

    wchar_t temp_guid_path[MAX_PATH];
    wcsncpy(temp_guid_path, volume_guid_path, MAX_PATH - 1);
    temp_guid_path[wcslen(temp_guid_path) - 1] = L'\0';
    LPCWSTR perflib_name = NULL;

    if (QueryDosDeviceW(&temp_guid_path[4], device_name, ARRAYSIZE(device_name))) {
        perflib_name = wcsstr(device_name, L"\\Device\\");
        if (perflib_name != NULL) {
            perflib_name += wcslen(L"\\Device\\");
            wcsncpy(out_buffer, perflib_name, out_buffer_size - 1);

            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}

static int we_logical_disk_update_from_api(struct flb_we *ctx)
{
    HANDLE h_find_volume = INVALID_HANDLE_VALUE;
    wchar_t volume_name_w[MAX_PATH] = {0};
    wchar_t path_names_w[MAX_PATH] = {0};
    wchar_t perflib_instance_name_w[MAX_PATH] = {0};
    wchar_t file_system_name_w[MAX_PATH] = {0};
    char volume_label_utf8[MAX_PATH] = {0};
    ULARGE_INTEGER free_bytes_available;
    ULARGE_INTEGER total_number_of_bytes;
    ULARGE_INTEGER total_number_of_free_bytes;
    uint64_t timestamp;

    timestamp = cfl_time_now();
    h_find_volume = FindFirstVolumeW(volume_name_w, ARRAYSIZE(volume_name_w));

    if (h_find_volume == INVALID_HANDLE_VALUE) {
        flb_plg_error(ctx->ins, "FindFirstVolumeW failed with error %lu", GetLastError());

        return -1;
    }

    do {
        DWORD path_names_len = 0;
        BOOL has_mount_point;

        if (GetVolumeInformationW(volume_name_w, NULL, 0, NULL, NULL, NULL,
                                  file_system_name_w, ARRAYSIZE(file_system_name_w))) {
            if (wcscmp(file_system_name_w, L"NTFS") != 0 &&
                wcscmp(file_system_name_w, L"ReFS") != 0) {
                /* Note: Skip volumes that are not NTFS or ReFS
                 * (e.g., FAT32 system partitions for UEFI etc.)
                 * This is because they are ephemeral volumes or rarely read/written by Windows systems.
                 */
                continue;
            }
        }
        else {
            continue;
        }

        has_mount_point = GetVolumePathNamesForVolumeNameW(volume_name_w,
                                                           path_names_w,
                                                           ARRAYSIZE(path_names_w),
                                                           &path_names_len) && path_names_w[0] != L'\0';

        if (has_mount_point) {
            wcstombs(volume_label_utf8, path_names_w, MAX_PATH - 1);
            size_t len = strlen(volume_label_utf8);
            if (len > 1 && (volume_label_utf8[len - 1] == '\\' || volume_label_utf8[len - 1] == '/')) {
                volume_label_utf8[len - 1] = '\0';
            }
        }
        else {
            if (we_get_volume_perflib_instance_name(volume_name_w,
                                                    perflib_instance_name_w,
                                                    ARRAYSIZE(perflib_instance_name_w))) {
                wcstombs(volume_label_utf8, perflib_instance_name_w, MAX_PATH - 1);
            }
            else {
                continue;
            }
        }

        /* Apply the same filtering logic as perflib */
        if (we_logical_disk_instance_hook(volume_label_utf8, ctx) != 0) {
            continue;
        }

        if (GetDiskFreeSpaceExW(volume_name_w,
                                &free_bytes_available,
                                &total_number_of_bytes,
                                &total_number_of_free_bytes)) {
            cmt_gauge_set(ctx->logical_disk.size_bytes, timestamp,
                          (double)total_number_of_bytes.QuadPart,
                          1, (char *[]) {volume_label_utf8});

            cmt_gauge_set(ctx->logical_disk.free_bytes, timestamp,
                          (double)total_number_of_free_bytes.QuadPart,
                          1, (char *[]) {volume_label_utf8});
        }
        else {
            flb_plg_warn(ctx->ins, "Could not get disk space for volume %s, error %lu",
                         volume_label_utf8, GetLastError());
        }
    } while (FindNextVolumeW(h_find_volume, volume_name_w, ARRAYSIZE(volume_name_w)));

    FindVolumeClose(h_find_volume);
    return 0;
}

int we_logical_disk_update(struct flb_we *ctx)
{
    int result;
    if (!ctx->logical_disk.operational) {
        flb_plg_error(ctx->ins, "logical_disk collector not yet in operational state");

        return -1;
    }

    /* Update I/O counters from Perflib */
    result = we_perflib_update_counters(ctx,
                                        ctx->logical_disk.query,
                                        ctx->logical_disk.metric_sources,
                                        we_logical_disk_instance_hook,
                                        we_logical_disk_label_prepend_hook);
    if (result != 0) {
        flb_plg_error(ctx->ins, "could not update logical_disk collector for perflib part");
    }

    /* Update size/free metrics from Windows API */
    result = we_logical_disk_update_from_api(ctx);
    if (result != 0) {
        flb_plg_error(ctx->ins, "could not update logical_disk collector for api part");
        return -1;
    }

    return 0;
}