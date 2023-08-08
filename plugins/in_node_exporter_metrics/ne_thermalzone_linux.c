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
#include "ne_thermalzone_linux.h"

#include <unistd.h>

/*
 * See kernel documentation for a description:
 * https://www.kernel.org/doc/html/latest/driver-api/thermal/sysfs-api.html
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
    ctx->thermalzone_temp = cmt_gauge_create(ctx->cmt, "node", "thermal_zone", "temp",
                                             "Zone temperature in Celsius",
                                             2, (char *[]) {"zone", "type"});
    if (!ctx->thermalzone_temp) {
        flb_plg_error(ctx->ins, "could not initialize thermal zone metrics");
        return -1;
    }

    ctx->cooling_device_cur_state = cmt_gauge_create(ctx->cmt, 
                                                     "node", "cooling_device", "cur_state",
                                                     "Current throttle state of the cooling device",
                                                     2, (char *[]) {"name", "type"});
    if (!ctx->cooling_device_cur_state) {
        flb_plg_error(ctx->ins, "could not initialize cooling device cur_state metric");
        return -1;
    }

    ctx->cooling_device_max_state = cmt_gauge_create(ctx->cmt,
                                                     "node", "cooling_device", "max_state",
                                                     "Maximum throttle state of the cooling device",
                                                     2, (char *[]) {"name", "type"});
    if (!ctx->cooling_device_max_state) {
        flb_plg_error(ctx->ins, "could not initialize cooling device max_state metric");
        return -1;
    }

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
    flb_sds_t full_path_sysfs;
    int path_sysfs_len;
    char *num;

    ts = cfl_time_now();

    ret = ne_utils_path_scan(ctx, ctx->path_sysfs, THERMAL_ZONE_PATTERN, NE_SCAN_DIR, &list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&list) == 0) {
        return 0;
    }

    full_path_sysfs = flb_sds_create_size(strlen(THERMAL_ZONE_BASE) + 
                                          strlen(ctx->path_sysfs) + 8);
    if (full_path_sysfs == NULL) {
        flb_slist_destroy(&list);
        return -1;
    }
    path_sysfs_len = strlen(ctx->path_sysfs);
    if (ctx->path_sysfs[strlen(ctx->path_sysfs)-1] == '/') {
        path_sysfs_len--;
    }
    /* Set the full_path to the sysfs path */
    if (flb_sds_cat_safe(&full_path_sysfs, ctx->path_sysfs, path_sysfs_len) < 0) {
        flb_slist_destroy(&list);
        flb_sds_destroy(full_path_sysfs);
        return -1;
    }
    /* Concatenate the base for all thermalzone objects */
    if (flb_sds_cat_safe(&full_path_sysfs, THERMAL_ZONE_BASE,
                         strlen(THERMAL_ZONE_BASE)) < 0) {
        flb_slist_destroy(&list);
        flb_sds_destroy(full_path_sysfs);
        return -1;
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

        if (strncmp(entry->str, full_path_sysfs, strlen(full_path_sysfs)) == 0) {
            num = &entry->str[strlen(full_path_sysfs)];
        } else {
            num = entry->str;
        }

        cmt_gauge_set(ctx->thermalzone_temp, ts, ((double) temp)/1000.0,
                    2, (char *[]) {num, type});

        flb_sds_destroy(type);
    }

    flb_slist_destroy(&list);
    flb_sds_destroy(full_path_sysfs);

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
    char *num;
    flb_sds_t full_path_sysfs;
    int path_sysfs_len;

    ts = cfl_time_now();

    ret = ne_utils_path_scan(ctx, ctx->path_sysfs, COOLING_DEVICE_PATTERN, NE_SCAN_DIR, &list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&list) == 0) {
        return 0;
    }

    full_path_sysfs = flb_sds_create_size(strlen(COOLING_DEVICE_BASE) + 
                                          strlen(ctx->path_sysfs) + 8);
    if (full_path_sysfs == NULL) {
        flb_slist_destroy(&list);
        return -1;
    }
    path_sysfs_len = strlen(ctx->path_sysfs);
    if (ctx->path_sysfs[strlen(ctx->path_sysfs)-1] == '/') {
        path_sysfs_len--;
    }
    if (flb_sds_cat_safe(&full_path_sysfs, ctx->path_sysfs, path_sysfs_len) < 0) {
        flb_slist_destroy(&list);
        flb_sds_destroy(full_path_sysfs);
        return -1;
    }
    if (flb_sds_cat_safe(&full_path_sysfs, COOLING_DEVICE_BASE,
                         strlen(COOLING_DEVICE_BASE)) < 0) {
        flb_slist_destroy(&list);
        flb_sds_destroy(full_path_sysfs);
        return -1;
    }

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

        if (strncmp(entry->str, full_path_sysfs, strlen(full_path_sysfs)) == 0) {
            num = &entry->str[strlen(full_path_sysfs)];
        } else {
            num = entry->str;
        }

        cmt_gauge_set(ctx->cooling_device_cur_state, ts, ((double)cur_state),
                    2, (char *[]) {num, type});
        cmt_gauge_set(ctx->cooling_device_max_state, ts, ((double)max_state),
                    2, (char *[]) {num, type});
        flb_sds_destroy(type);
    }

    flb_slist_destroy(&list);
    flb_sds_destroy(full_path_sysfs);

    return 0;
}
