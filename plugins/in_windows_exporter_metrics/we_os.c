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

#ifndef UNICODE
#define UNICODE
#endif
#include <lm.h>
#include <psapi.h>
#include <timezoneapi.h>

#include "we.h"
#include "we_os.h"
#include "we_util.h"
#include "we_metric.h"

int we_os_init(struct flb_we *ctx)
{
    ctx->os = flb_calloc(1, sizeof(struct we_os_counters));
    if (!ctx->os) {
        flb_errno();
        return -1;
    }
    ctx->os->operational = FLB_FALSE;

    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "info",
                         "Version information of OperatingSystem",
                         5, (char *[]) {"product", "version", "major_version", "minor_version", "build_number"});

    if (!g) {
        return -1;
    }
    ctx->os->info = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "physical_memory_free_bytes",
                         "Amount of free bytes of physical memory",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->physical_memory_free_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "time",
                         "Value of Local Time",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->os->time = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "timezone",
                         "Name of Local Timezone",
                         1, (char *[]) {"timezone"});
    if (!g) {
        return -1;
    }
    ctx->os->tz = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "virtual_memory_bytes",
                         "Total amount of bytes of virtual memory",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->virtual_memory_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "processes_limit",
                         "Number of processes limit",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->processes_limit = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "process_memory_limit_bytes",
                         "Limit of processes memory",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->process_memory_limit_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "processes",
                         "Number of processes",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->processes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "users",
                         "Number of users",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->users = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "visible_memory_bytes",
                         "Total amount of bytes of visibile memory",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->visible_memory_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "os", "virtual_memory_free_bytes",
                         "Amount of free bytes of virtual memory",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->os->virtual_memory_free_bytes = g;

    ctx->os->operational = FLB_TRUE;

    return 0;
}

int we_os_exit(struct flb_we *ctx)
{
    flb_free(ctx->os);
    return 0;
}

int we_os_update(struct flb_we *ctx)
{
    DWORD level = 102;
    LPWKSTA_INFO_102 wksta = NULL;
    NET_API_STATUS status;
    MEMORYSTATUSEX statex;
    PERFORMANCE_INFORMATION perf;
    DWORD size = 0;
    char version[65] = {0}, major[32] = {0}, minor[32] = {0};
    int users = 0;
    LONG ret;
    HKEY hkey;
    char caption[80], build_number[32];
    DWORD caption_len = sizeof(caption), build_len = sizeof(build_number);
    uint64_t timestamp = 0;
    char label_caption[90];
    DYNAMIC_TIME_ZONE_INFORMATION dtzi;
    DWORD tztype = 0;
    char *displaytz;

    if (!ctx->os->operational) {
        flb_plg_error(ctx->ins, "os collector not yet in operational state");

        return -1;
    }

    timestamp = cfl_time_now();

    ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WE_OS_CURRENT_VERSION_PATH, 0, KEY_QUERY_VALUE, &hkey);
    if (ret != ERROR_SUCCESS) {
        return -1;
    }
    ret = RegQueryValueExA(hkey, "ProductName", NULL, NULL, (LPBYTE)caption, &caption_len);
    if (ret != ERROR_SUCCESS) {
        return -1;
    }
    ret = RegQueryValueExA(hkey, "CurrentBuildNumber", NULL, NULL, (LPBYTE)build_number, &build_len);
    if (ret != ERROR_SUCCESS) {
        return -1;
    }
    RegCloseKey(hkey);

    status = NetWkstaGetInfo(NULL,
                             level,
                             (LPBYTE *)&wksta);

    if (status == NERR_Success) {
        snprintf(version, 65, "%d.%d", wksta->wki102_ver_major,
                 wksta->wki102_ver_minor);
        snprintf(major, 32, "%d", wksta->wki102_ver_major);
        snprintf(minor, 32, "%d", wksta->wki102_ver_minor);
        snprintf(label_caption, 90, "Microsoft %s", caption);

        users = wksta->wki102_logged_on_users;

        cmt_gauge_set(ctx->os->info, timestamp, 1.0, 5,
                      (char *[]) { label_caption, version, major, minor, build_number});
        cmt_gauge_set(ctx->os->users, timestamp, (double)users, 0, NULL);
    }
    else {
        if (wksta != NULL) {
            NetApiBufferFree(wksta);
        }
        flb_plg_error(ctx->ins, "A system error has occurred: %d\n", status);
        return -1;
    }

    cmt_gauge_set(ctx->os->time, timestamp, (double)timestamp/1000000000L, 0, NULL);

    _tzset();

    tztype = GetDynamicTimeZoneInformation(&dtzi);
    switch (tztype) {
    case TIME_ZONE_ID_STANDARD:
        displaytz = we_convert_wstr(dtzi.StandardName, CP_UTF8);
        cmt_gauge_set(ctx->os->tz, timestamp, 1.0, 1, (char *[]) {displaytz});
        flb_free(displaytz);
        break;
    case TIME_ZONE_ID_DAYLIGHT:
        displaytz = we_convert_wstr(dtzi.DaylightName, CP_UTF8);
        cmt_gauge_set(ctx->os->tz, timestamp, 1.0, 1, (char *[]) {displaytz});
        flb_free(displaytz);
        break;
    case TIME_ZONE_ID_UNKNOWN:
        /* The current timezone does not use daylight saving time. */
        displaytz = we_convert_wstr(dtzi.StandardName, CP_UTF8);
        cmt_gauge_set(ctx->os->tz, timestamp, 1.0, 1, (char *[]) {displaytz});
        flb_free(displaytz);
        break;
    default:
        flb_plg_error(ctx->ins, "Error to retrieve timezone information with status: %d", GetLastError());
    }

    statex.dwLength = sizeof (statex);
    GlobalMemoryStatusEx(&statex);

    size = sizeof(perf);
    GetPerformanceInfo(&perf, size);

    cmt_gauge_set(ctx->os->physical_memory_free_bytes, timestamp, (double)statex.ullAvailPhys, 0, NULL);
    cmt_gauge_set(ctx->os->virtual_memory_free_bytes, timestamp, (double)statex.ullAvailPageFile, 0, NULL);
    /* The result is from $(Get-WMIObject Win32_OperatingSystem).MaxNumberOfProcesses. */
    cmt_gauge_set(ctx->os->processes_limit, timestamp, (double)4294967295, 0, NULL);
    cmt_gauge_set(ctx->os->process_memory_limit_bytes, timestamp, (double)statex.ullTotalVirtual, 0, NULL);
    cmt_gauge_set(ctx->os->processes, timestamp, (double)perf.ProcessCount, 0, NULL);
    cmt_gauge_set(ctx->os->virtual_memory_bytes, timestamp, (double)statex.ullTotalPageFile, 0, NULL);
    cmt_gauge_set(ctx->os->visible_memory_bytes, timestamp, (double)statex.ullTotalPhys, 0, NULL);

    if (wksta != NULL) {
        NetApiBufferFree(wksta);
    }

    return 0;
}
