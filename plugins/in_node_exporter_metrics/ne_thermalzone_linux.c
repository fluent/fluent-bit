/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>

/*
 * See kernel documentation for a description:
 * https://www.kernel.org/doc/html/latest/filesystems/proc.html
 *
 * user: normal processes executing in user mode
 * nice: niced processes executing in user mode
 * system: processes executing in kernel mode
 * idle: twiddling thumbs
 * iowait: In a word, iowait stands for waiting for I/O to complete. But there are several problems:
 * irq: servicing interrupts
 * softirq: servicing softirqs
 * steal: involuntary wait
 * guest: running a normal guest
 * guest_nice: running a niced guest
 *
 * Ensure to pick the correct version of the documentation, older versions here:
 * https://github.com/torvalds/linux/tree/master/Documentation
 */
/*
 * Thermal zone stats, reads /sys/class/thermal/thermal_zone*
 * ----------------------------------------------------------
 */

int ne_thermalzone_init(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "node", "thermal_zone", "temp",
                           "Zone temperature in Celsius",
                           2, (char *[]) {"zone", "type"});
    if (!g) {
        flb_plg_error(ctx->ins, "could not initialize thermal zone metrics");
        return -1;
    }
    ctx->thermalzone_temp = g;

    g = cmt_gauge_create(ctx->cmt, "node", "cooling_device", "cur_state",
                         "Current throttle state of the cooling device",
                          2, (char *[]) {"name", "type"});
    if (!g) {
        flb_plg_error(ctx->ins, "could not initialize cooling device cur_state metric");
        return -1;
    }
    ctx->cooling_device_cur_state = g;

    g = cmt_gauge_create(ctx->cmt, "node", "cooling_device", "max_state",
                         "Maximum throttle state of the cooling device",
                          2, (char *[]) {"name", "type"});
    if (!g) {
        flb_plg_error(ctx->ins, "could not initialize cooling device max_state metric");
        return -1;
    }
    ctx->cooling_device_max_state = g;
    return 0;
}

int ne_thermalzone_update_thermal_zones(struct flb_ne *ctx)
{
    uint64_t ts;
    int ret;
    uint64_t temp = 0;
    struct mk_list *head;
    struct mk_list list;
    struct flb_slist_entry *entry;
    flb_sds_t type;
    const char *pattern = "/class/thermal/thermal_zone[0-9]*";

    ts = cfl_time_now();

    ret = ne_utils_path_scan(ctx, ctx->path_sysfs, pattern, NE_SCAN_DIR, &list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&list) == 0) {
        return 0;
    }

    /* Process entries */
    mk_list_foreach(head, &list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* Core ID */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str,
                                        "temp", NULL,
                                        &temp);
        if (ret != 0) {
            continue;
        }

        ret = ne_utils_file_read_sds(ctx->path_sysfs, entry->str, "type", NULL, &type);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "unable to get type for zone: %s", entry->str);
            continue;
        }

        cmt_gauge_set(ctx->thermalzone_temp, ts, ((double)temp)/1000.0,
                    2, (char *[]) {&entry->str[strlen("/sys/class/thermal/thermal_zone")], type});
        flb_sds_destroy(type);
    }

    flb_slist_destroy(&list);

    return 0;
}

int ne_thermalzone_update_cooling_devices(struct flb_ne *ctx)
{
    uint64_t ts;
    int ret;
    uint64_t cur_state = 0;
    uint64_t max_state = 0;
    struct mk_list *head;
    struct mk_list list;
    struct flb_slist_entry *entry;
    flb_sds_t type;
    const char *pattern = "/class/thermal/cooling_device[0-9]*";
    /* Status arrays */
    uint64_t core_throttles_set[32][256];
    uint64_t package_throttles_set[32];

    ts = cfl_time_now();

    ret = ne_utils_path_scan(ctx, ctx->path_sysfs, pattern, NE_SCAN_DIR, &list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&list) == 0) {
        return 0;
    }

    /* Reset arrays status */
    memset(&core_throttles_set, 0, sizeof(core_throttles_set));
    memset(&package_throttles_set, 0, sizeof(package_throttles_set));

    /* Process entries */
    mk_list_foreach(head, &list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* Core ID */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str,
                                        "cur_state", NULL,
                                        &cur_state);
        if (ret != 0) {
            continue;
        }

        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str,
                                        "max_state", NULL,
                                        &max_state);
        if (ret != 0) {
            continue;
        }

        ret = ne_utils_file_read_sds(ctx->path_sysfs, entry->str, "type", NULL, &type);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "unable to get type for zone: %s", entry->str);
            continue;
        }

        cmt_gauge_set(ctx->cooling_device_cur_state, ts, ((double)cur_state),
                    2, (char *[]) {&entry->str[strlen("/sys/class/thermal/cooling_device")], type});
        cmt_gauge_set(ctx->cooling_device_max_state, ts, ((double)max_state),
                    2, (char *[]) {&entry->str[strlen("/sys/class/thermal/cooling_device")], type});
        flb_sds_destroy(type);
    }

    flb_slist_destroy(&list);

    return 0;
}