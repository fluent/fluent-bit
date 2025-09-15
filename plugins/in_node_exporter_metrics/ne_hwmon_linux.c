/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include "ne_hwmon_linux.h"

#include <unistd.h>
#include <string.h>

static int hwmon_filter_match(struct flb_regex *include, struct flb_regex *exclude,
                              const char *name)
{
    size_t len;

    len = strlen(name);

    if (include) {
        if (flb_regex_match(include, (unsigned char *) name, len) == 0) {
            return FLB_FALSE;
        }
    }

    if (exclude) {
        if (flb_regex_match(exclude, (unsigned char *) name, len) == 1) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int ne_hwmon_init(struct flb_ne *ctx)
{
    /* create metrics */
    ctx->hwmon_temp_celsius = cmt_gauge_create(ctx->cmt, "node", "hwmon",
                                               "temp_celsius",
                                               "Hardware monitor temperature sensor data in degrees celsius",
                                               2, (char *[]) {"chip", "sensor"});
    if (!ctx->hwmon_temp_celsius) {
        flb_plg_error(ctx->ins, "could not initialize hwmon temperature metric");
        return -1;
    }

    ctx->hwmon_temp_max_celsius = cmt_gauge_create(ctx->cmt, "node", "hwmon",
                                                   "temp_max_celsius",
                                                   "Hardware monitor temperature maximum in degrees celsius",
                                                   2, (char *[]) {"chip", "sensor"});
    if (!ctx->hwmon_temp_max_celsius) {
        flb_plg_error(ctx->ins, "could not initialize hwmon temp max metric");
        return -1;
    }

    ctx->hwmon_temp_crit_celsius = cmt_gauge_create(ctx->cmt, "node", "hwmon",
                                                    "temp_crit_celsius",
                                                    "Hardware monitor temperature critical in degrees celsius",
                                                    2, (char *[]) {"chip", "sensor"});
    if (!ctx->hwmon_temp_crit_celsius) {
        flb_plg_error(ctx->ins, "could not initialize hwmon temp crit metric");
        return -1;
    }

    ctx->hwmon_in_volts = cmt_gauge_create(ctx->cmt, "node", "hwmon",
                                           "in_volts",
                                           "Hardware monitor voltage sensor data in volts",
                                           2, (char *[]) {"chip", "sensor"});
    if (!ctx->hwmon_in_volts) {
        flb_plg_error(ctx->ins, "could not initialize hwmon voltage metric");
        return -1;
    }

    ctx->hwmon_fan_rpm = cmt_gauge_create(ctx->cmt, "node", "hwmon",
                                          "fan_rpm",
                                          "Hardware monitor fan speed in rotations per minute",
                                          2, (char *[]) {"chip", "sensor"});
    if (!ctx->hwmon_fan_rpm) {
        flb_plg_error(ctx->ins, "could not initialize hwmon fan metric");
        return -1;
    }

    ctx->hwmon_power_watts = cmt_gauge_create(ctx->cmt, "node", "hwmon",
                                              "power_watts",
                                              "Hardware monitor power sensor data in watts",
                                              2, (char *[]) {"chip", "sensor"});
    if (!ctx->hwmon_power_watts) {
        flb_plg_error(ctx->ins, "could not initialize hwmon power metric");
        return -1;
    }

    if (ctx->hwmon_chip_regex_include_text) {
        ctx->hwmon_chip_regex_include =
            flb_regex_create(ctx->hwmon_chip_regex_include_text);
        if (!ctx->hwmon_chip_regex_include) {
            flb_plg_error(ctx->ins, "could not compile hwmon chip include regex");
            return -1;
        }
    }

    if (ctx->hwmon_chip_regex_exclude_text) {
        ctx->hwmon_chip_regex_exclude =
            flb_regex_create(ctx->hwmon_chip_regex_exclude_text);
        if (!ctx->hwmon_chip_regex_exclude) {
            flb_plg_error(ctx->ins, "could not compile hwmon chip exclude regex");
            return -1;
        }
    }

    if (ctx->hwmon_sensor_regex_include_text) {
        ctx->hwmon_sensor_regex_include =
            flb_regex_create(ctx->hwmon_sensor_regex_include_text);
        if (!ctx->hwmon_sensor_regex_include) {
            flb_plg_error(ctx->ins, "could not compile hwmon sensor include regex");
            return -1;
        }
    }

    if (ctx->hwmon_sensor_regex_exclude_text) {
        ctx->hwmon_sensor_regex_exclude =
            flb_regex_create(ctx->hwmon_sensor_regex_exclude_text);
        if (!ctx->hwmon_sensor_regex_exclude) {
            flb_plg_error(ctx->ins, "could not compile hwmon sensor exclude regex");
            return -1;
        }
    }

    return 0;
}

static void hwmon_process_sensor(struct flb_ne *ctx, const char *chip_path,
                                 const char *chip_name, const char *sensor_path,
                                 uint64_t tstamp)
{
    char *base;
    char sensor_name[128];
    size_t base_len;
    uint64_t val;
    int ret;
    char label_name[160];
    flb_sds_t label = NULL;
    const char *sensor_label;
    char file_tmp[160];

    base = strrchr(sensor_path, '/');
    if (!base) {
        return;
    }
    base++;
    base_len = strlen(base);
    if (base_len < 6) {
        return;
    }
    if (strcmp(base + base_len - 6, "_input") != 0) {
        return;
    }

    if (base_len - 6 >= sizeof(sensor_name)) {
        return;
    }
    memcpy(sensor_name, base, base_len - 6);
    sensor_name[base_len - 6] = '\0';

    if (!hwmon_filter_match(ctx->hwmon_sensor_regex_include,
                            ctx->hwmon_sensor_regex_exclude,
                            sensor_name)) {
        return;
    }

    /* read input value */
    ret = ne_utils_file_read_uint64(ctx->path_sysfs, sensor_path,
                                    NULL, NULL, &val);
    if (ret != 0) {
        return;
    }

    snprintf(label_name, sizeof(label_name) - 1, "%s_label", sensor_name);
    if (ne_utils_file_read_sds(ctx->path_sysfs, chip_path,
                               label_name, NULL, &label) == 0) {
        sensor_label = label;
    }
    else {
        sensor_label = sensor_name;
    }

    if (strncmp(sensor_name, "temp", 4) == 0) {
        cmt_gauge_set(ctx->hwmon_temp_celsius, tstamp,
                      ((double) val) / 1000.0,
                      2, (char *[]) {(char *) chip_name, (char *) sensor_label});

        snprintf(file_tmp, sizeof(file_tmp) - 1, "%s_max", sensor_name);
        if (ne_utils_file_read_uint64(ctx->path_sysfs, chip_path,
                                       file_tmp, NULL, &val) == 0) {
            cmt_gauge_set(ctx->hwmon_temp_max_celsius, tstamp,
                          ((double) val) / 1000.0,
                          2, (char *[]) {(char *) chip_name, (char *) sensor_label});
        }

        snprintf(file_tmp, sizeof(file_tmp) - 1, "%s_crit", sensor_name);
        if (ne_utils_file_read_uint64(ctx->path_sysfs, chip_path,
                                       file_tmp, NULL, &val) == 0) {
            cmt_gauge_set(ctx->hwmon_temp_crit_celsius, tstamp,
                          ((double) val) / 1000.0,
                          2, (char *[]) {(char *) chip_name, (char *) sensor_label});
        }
    }
    else if (strncmp(sensor_name, "in", 2) == 0) {
        cmt_gauge_set(ctx->hwmon_in_volts, tstamp,
                      ((double) val) / 1000.0,
                      2, (char *[]) {(char *) chip_name, (char *) sensor_label});
    }
    else if (strncmp(sensor_name, "fan", 3) == 0) {
        cmt_gauge_set(ctx->hwmon_fan_rpm, tstamp, (double) val,
                      2, (char *[]) {(char *) chip_name, (char *) sensor_label});
    }
    else if (strncmp(sensor_name, "power", 5) == 0) {
        cmt_gauge_set(ctx->hwmon_power_watts, tstamp,
                      ((double) val) / 1000000.0,
                      2, (char *[]) {(char *) chip_name, (char *) sensor_label});
    }

    if (label) {
        flb_sds_destroy(label);
    }
}

static int ne_hwmon_update(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;
    struct mk_list hwmons;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    flb_sds_t pattern;
    struct mk_list sensors;
    struct mk_list *shead;
    struct flb_slist_entry *sentry;
    flb_sds_t chip;
    uint64_t tstamp;
    int ret;
    int base_len;
    const char *chip_rel;

    tstamp = cfl_time_now();

    ret = ne_utils_path_scan(ctx, ctx->path_sysfs, HWMON_PATTERN,
                             NE_SCAN_DIR, &hwmons);
    if (ret != 0) {
        return -1;
    }

    mk_list_foreach(head, &hwmons) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        if (ne_utils_file_read_sds(ctx->path_sysfs, entry->str,
                                   "name", NULL, &chip) != 0) {
            continue;
        }

        if (!hwmon_filter_match(ctx->hwmon_chip_regex_include,
                                ctx->hwmon_chip_regex_exclude,
                                chip)) {
            flb_sds_destroy(chip);
            continue;
        }

        /* Build pattern to find all *_input files under the chip */
        base_len = strlen(ctx->path_sysfs);
        if (ctx->path_sysfs[base_len - 1] == '/') {
            base_len--;
        }
        chip_rel = entry->str + base_len;

        pattern = flb_sds_create(chip_rel);
        if (!pattern) {
            flb_sds_destroy(chip);
            continue;
        }
        if (flb_sds_cat_safe(&pattern, "/*_input", 8) < 0) {
            flb_sds_destroy(pattern);
            flb_sds_destroy(chip);
            continue;
        }

        ret = ne_utils_path_scan(ctx, ctx->path_sysfs, pattern,
                                 NE_SCAN_FILE, &sensors);
        flb_sds_destroy(pattern);
        if (ret != 0) {
            flb_sds_destroy(chip);
            continue;
        }

        mk_list_foreach(shead, &sensors) {
            sentry = mk_list_entry(shead, struct flb_slist_entry, _head);
            hwmon_process_sensor(ctx, entry->str, chip, sentry->str, tstamp);
        }

        flb_slist_destroy(&sensors);
        flb_sds_destroy(chip);
    }

    flb_slist_destroy(&hwmons);
    return 0;
}

static int ne_hwmon_exit(struct flb_ne *ctx)
{
    if (ctx->hwmon_chip_regex_include) {
        flb_regex_destroy(ctx->hwmon_chip_regex_include);
    }
    if (ctx->hwmon_chip_regex_exclude) {
        flb_regex_destroy(ctx->hwmon_chip_regex_exclude);
    }
    if (ctx->hwmon_sensor_regex_include) {
        flb_regex_destroy(ctx->hwmon_sensor_regex_include);
    }
    if (ctx->hwmon_sensor_regex_exclude) {
        flb_regex_destroy(ctx->hwmon_sensor_regex_exclude);
    }
    return 0;
}

struct flb_ne_collector hwmon_collector = {
    .name = "hwmon",
    .cb_init = ne_hwmon_init,
    .cb_update = ne_hwmon_update,
    .cb_exit = ne_hwmon_exit
};

