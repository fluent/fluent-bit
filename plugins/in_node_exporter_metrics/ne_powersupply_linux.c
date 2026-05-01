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

#include <dirent.h>
#include <stdio.h>
#include <string.h>

#include "ne.h"

struct ps_metric_spec {
    const char *metric_name;
    const char *file_name;
    double divisor;
};

struct ps_metric_entry {
    char *name;
    struct cmt_gauge *gauge;
    struct mk_list _head;
};

static void ps_dynamic_metrics_destroy(struct flb_ne *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct ps_metric_entry *entry;

    mk_list_foreach_safe(head, tmp, &ctx->powersupply_dynamic_metrics) {
        entry = mk_list_entry(head, struct ps_metric_entry, _head);
        mk_list_del(&entry->_head);
        if (entry->name != NULL) {
            flb_free(entry->name);
        }
        flb_free(entry);
    }
}

static int ne_powersupply_exit(struct flb_ne *ctx)
{
    ps_dynamic_metrics_destroy(ctx);
    return 0;
}

static struct ps_metric_spec ps_numeric_metrics[] = {
    {"authentic", "authentic", 1.0},
    {"calibrate", "calibrate", 1.0},
    {"capacity", "capacity", 1.0},
    {"capacity_alert_max", "capacity_alert_max", 1.0},
    {"capacity_alert_min", "capacity_alert_min", 1.0},
    {"cyclecount", "cycle_count", 1.0},
    {"online", "online", 1.0},
    {"present", "present", 1.0},
    {"time_to_empty_seconds", "time_to_empty_now", 1.0},
    {"time_to_full_seconds", "time_to_full_now", 1.0},
    {"current_boot", "current_boot", 1000000.0},
    {"current_max", "current_max", 1000000.0},
    {"current_ampere", "current_now", 1000000.0},
    {"energy_empty", "energy_empty", 1000000.0},
    {"energy_empty_design", "energy_empty_design", 1000000.0},
    {"energy_full", "energy_full", 1000000.0},
    {"energy_full_design", "energy_full_design", 1000000.0},
    {"energy_watthour", "energy_now", 1000000.0},
    {"voltage_boot", "voltage_boot", 1000000.0},
    {"voltage_max", "voltage_max", 1000000.0},
    {"voltage_max_design", "voltage_max_design", 1000000.0},
    {"voltage_min", "voltage_min", 1000000.0},
    {"voltage_min_design", "voltage_min_design", 1000000.0},
    {"voltage_volt", "voltage_now", 1000000.0},
    {"voltage_ocv", "voltage_ocv", 1000000.0},
    {"charge_control_limit", "charge_control_limit", 1000000.0},
    {"charge_control_limit_max", "charge_control_limit_max", 1000000.0},
    {"charge_counter", "charge_counter", 1000000.0},
    {"charge_empty", "charge_empty", 1000000.0},
    {"charge_empty_design", "charge_empty_design", 1000000.0},
    {"charge_full", "charge_full", 1000000.0},
    {"charge_full_design", "charge_full_design", 1000000.0},
    {"charge_ampere", "charge_now", 1000000.0},
    {"charge_term_current", "charge_term_current", 1000000.0},
    {"constant_charge_current", "constant_charge_current", 1000000.0},
    {"constant_charge_current_max", "constant_charge_current_max", 1000000.0},
    {"constant_charge_voltage", "constant_charge_voltage", 1000000.0},
    {"constant_charge_voltage_max", "constant_charge_voltage_max", 1000000.0},
    {"precharge_current", "precharge_current", 1000000.0},
    {"input_current_limit", "input_current_limit", 1000000.0},
    {"power_watt", "power_now", 1000000.0},
    {"temp_celsius", "temp", 10.0},
    {"temp_alert_max_celsius", "temp_alert_max", 10.0},
    {"temp_alert_min_celsius", "temp_alert_min", 10.0},
    {"temp_ambient_celsius", "temp_ambient", 10.0},
    {"temp_ambient_max_celsius", "temp_ambient_max", 10.0},
    {"temp_ambient_min_celsius", "temp_ambient_min", 10.0},
    {"temp_max_celsius", "temp_max", 10.0},
    {"temp_min_celsius", "temp_min", 10.0},
};

static int read_long_file(const char *path, long *out)
{
    FILE *fp;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    if (fscanf(fp, "%ld", out) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static struct cmt_gauge *ps_metric_get(struct flb_ne *ctx, const char *name)
{
    struct mk_list *head;
    struct ps_metric_entry *entry;

    mk_list_foreach(head, &ctx->powersupply_dynamic_metrics) {
        entry = mk_list_entry(head, struct ps_metric_entry, _head);
        if (strcmp(entry->name, name) == 0) {
            return entry->gauge;
        }
    }

    entry = flb_calloc(1, sizeof(struct ps_metric_entry));
    if (entry == NULL) {
        return NULL;
    }
    entry->name = flb_strdup(name);
    if (entry->name == NULL) {
        flb_free(entry);
        return NULL;
    }

    entry->gauge = cmt_gauge_create(ctx->cmt, "node", "powersupply", name,
                                    "Power supply metric from /sys/class/power_supply.",
                                    1, (char *[]) {"power_supply"});
    if (entry->gauge == NULL) {
        flb_free(entry->name);
        flb_free(entry);
        return NULL;
    }

    mk_list_add(&entry->_head, &ctx->powersupply_dynamic_metrics);
    return entry->gauge;
}

static void emit_info_metric(struct flb_ne *ctx, const char *name, uint64_t ts)
{
    char *labels[] = {(char *) name};

    (void) ctx;
    cmt_gauge_set(ctx->powersupply_info, ts, 1.0, 1, labels);
}

static int update_one(struct flb_ne *ctx, const char *name)
{
    size_t i;
    long v;
    uint64_t ts;
    char path[1024];
    char *labels[] = {(char *) name};
    struct cmt_gauge *gauge;

    ts = cfl_time_now();

    for (i = 0; i < sizeof(ps_numeric_metrics) / sizeof(ps_numeric_metrics[0]); i++) {
        snprintf(path, sizeof(path) - 1, "%s/class/power_supply/%s/%s",
                 ctx->path_sysfs, name, ps_numeric_metrics[i].file_name);

        if (read_long_file(path, &v) == 0) {
            gauge = ps_metric_get(ctx, ps_numeric_metrics[i].metric_name);
            if (gauge != NULL) {
                cmt_gauge_set(gauge, ts, ((double) v) / ps_numeric_metrics[i].divisor,
                              1, labels);
            }
        }
    }

    emit_info_metric(ctx, name, ts);
    return 0;
}

static int ne_powersupply_init(struct flb_ne *ctx)
{
    mk_list_init(&ctx->powersupply_dynamic_metrics);
    ctx->powersupply_info = cmt_gauge_create(ctx->cmt, "node", "powersupply", "info",
                                             "info of /sys/class/power_supply/<power_supply>.",
                                             1, (char *[]) {"power_supply"});
    return 0;
}

static int ne_powersupply_update(struct flb_input_instance *ins,
                                 struct flb_config *config, void *in_context)
{
    DIR *dir;
    struct dirent *ent;
    struct flb_ne *ctx;
    char path[1024];

    (void) ins;
    (void) config;

    ctx = in_context;
    snprintf(path, sizeof(path) - 1, "%s/class/power_supply", ctx->path_sysfs);
    dir = opendir(path);
    if (dir == NULL) {
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        update_one(ctx, ent->d_name);
    }

    closedir(dir);
    return 0;
}

struct flb_ne_collector powersupply_collector = {
    .name = "powersupplyclass",
    .cb_init = ne_powersupply_init,
    .cb_update = ne_powersupply_update,
    .cb_exit = ne_powersupply_exit
};
