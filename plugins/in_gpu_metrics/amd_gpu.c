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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>

#include "gpu_common.h"
#include "amd_gpu.h"

#define AMD_VENDOR_ID "0x1002"

static const char *sysfs_path = "/sys";

static flb_sds_t build_path(int card_id, const char *file)
{
    flb_sds_t path = NULL;
    path = flb_sds_create_size(256); /* Allocate initial buffer */
    if (!path) {
        return NULL;
    }
    path = flb_sds_printf(&path, "%s/class/drm/card%d/device/%s", sysfs_path, card_id, file);
    return path;
}

static int match_card_pattern(const char *pattern, int card_id)
{
    char *dup;
    char *token;
    char *saveptr;
    int start;
    int end;

    if (!pattern || pattern[0] == '\0' || strcmp(pattern, "*") == 0) {
        return FLB_TRUE;
    }

    dup = flb_strdup(pattern);
    if (!dup) {
        return FLB_FALSE;
    }

    token = strtok_r(dup, ",", &saveptr);
    while (token) {
        if (sscanf(token, "%d-%d", &start, &end) == 2) {
            if (card_id >= start && card_id <= end) {
                flb_free(dup);
                return FLB_TRUE;
            }
        }
        else {
            if (card_id == atoi(token)) {
                flb_free(dup);
                return FLB_TRUE;
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    flb_free(dup);
    return FLB_FALSE;
}

static int should_include_card(struct in_gpu_metrics *ctx, int card_id)
{
    flb_plg_info(ctx->ins, "should_include_card: card%d, exclude='%s', include='%s'",
                 card_id, ctx->cards_exclude ? ctx->cards_exclude : "NULL",
                 ctx->cards_include ? ctx->cards_include : "NULL");

    if (ctx->cards_exclude && ctx->cards_exclude[0] != '\0' && match_card_pattern(ctx->cards_exclude, card_id)) {
        flb_plg_info(ctx->ins, "Card%d excluded by exclude pattern", card_id);
        return FLB_FALSE;
    }
    if (ctx->cards_include && ctx->cards_include[0] != '\0' && !match_card_pattern(ctx->cards_include, card_id)) {
        flb_plg_info(ctx->ins, "Card%d excluded by include pattern", card_id);
        return FLB_FALSE;
    }
    flb_plg_info(ctx->ins, "Card%d should be included", card_id);
    return FLB_TRUE;
}

static void free_cards(struct in_gpu_metrics *ctx)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct gpu_card *card;

    cfl_list_foreach_safe(head, tmp, &ctx->cards) {
        card = cfl_list_entry(head, struct gpu_card, _head);
        cfl_list_del(&card->_head);
        if (card->hwmon_path) {
            flb_sds_destroy(card->hwmon_path);
        }
        flb_free(card);
    }
}

static flb_sds_t find_hwmon_path(int card_id)
{
    char name[64];
    flb_sds_t path = NULL;
    flb_sds_t name_path = NULL;
    flb_sds_t hwmon_path = NULL;
    DIR *dir;
    struct dirent *entry;

    path = flb_sds_create_size(256); /* Allocate initial buffer */
    if (!path) {
        return NULL;
    }
    path = flb_sds_printf(&path, "%s/class/drm/card%d/device/hwmon", sysfs_path, card_id);
    if (!path) {
        return NULL;
    }
    dir = opendir(path);
    if (!dir) {
        flb_sds_destroy(path);
        return NULL;
    }

    while ((entry = readdir(dir))) {
        if (strncmp(entry->d_name, "hwmon", 5) != 0) {
            continue;
        }
        flb_sds_destroy(name_path);
        name_path = flb_sds_create_size(256); /* Allocate initial buffer */
        if (!name_path) {
            continue;
        }
        name_path = flb_sds_printf(&name_path, "%s/class/drm/card%d/device/hwmon/%s/name",
                                   sysfs_path, card_id, entry->d_name);
        if (!name_path) {
            continue;
        }
        if (gpu_read_line(name_path, name, sizeof(name)) == 0) {
            if (strncmp(name, "amdgpu", 6) == 0) {
                hwmon_path = flb_sds_create_size(256); /* Allocate initial buffer */
                if (!hwmon_path) {
                    flb_sds_destroy(name_path);
                    flb_sds_destroy(path);
                    closedir(dir);
                    return NULL;
                }
                hwmon_path = flb_sds_printf(&hwmon_path, "%s/class/drm/card%d/device/hwmon/%s",
                                           sysfs_path, card_id, entry->d_name);
                flb_sds_destroy(name_path);
                flb_sds_destroy(path);
                closedir(dir);
                return hwmon_path;
            }
        }
        flb_sds_destroy(name_path);
        name_path = NULL;
    }
    flb_sds_destroy(path);
    closedir(dir);
    return NULL;
}

int amd_gpu_detect_cards(struct in_gpu_metrics *ctx)
{
    DIR *dir;
    int id;
    char vendor[32];
    struct dirent *entry;
    flb_sds_t path = NULL;
    flb_sds_t vendor_path = NULL;
    struct gpu_card *card;

    /* Check if cards have already been detected */
    if (ctx->cards_detected) {
        flb_plg_debug(ctx->ins, "Cards already detected, skipping detection");
        return 0;
    }

    sysfs_path = ctx->path_sysfs ? ctx->path_sysfs : "/sys";
    flb_plg_info(ctx->ins, "Starting AMD GPU detection in %s", sysfs_path);

    path = flb_sds_create_size(256); /* Allocate initial buffer */
    if (!path) {
        flb_plg_warn(ctx->ins, "failed to allocate path buffer");
        return -1;
    }
    path = flb_sds_printf(&path, "%s/class/drm", sysfs_path);
    if (!path) {
        flb_plg_warn(ctx->ins, "failed to create path for class/drm");
        return -1;
    }
    if (access(path, F_OK) != 0) {
        flb_plg_warn(ctx->ins, "%s not found", path);
        flb_sds_destroy(path);
        return 0;
    }

    dir = opendir(path);
    if (!dir) {
        flb_plg_warn(ctx->ins, "could not open %s", path);
        flb_sds_destroy(path);
        return -1;
    }

    while ((entry = readdir(dir))) {
        /* Only match exact "cardX" pattern, not "cardX-*" */
        if (strncmp(entry->d_name, "card", 4) != 0) {
            continue;
        }

        /* Skip entries that have additional parts after the card number */
        if (strlen(entry->d_name) > 5 && entry->d_name[5] != '\0') {
            continue;
        }
        id = atoi(entry->d_name + 4);
        flb_plg_info(ctx->ins, "Found card%d", id);

        flb_sds_destroy(vendor_path);
        vendor_path = flb_sds_create_size(256);
        if (!vendor_path) {
            flb_plg_debug(ctx->ins, "failed to allocate vendor path buffer");
            continue;
        }

        vendor_path = flb_sds_printf(&vendor_path, "%s/class/drm/%s/device/vendor", sysfs_path, entry->d_name);
        if (!vendor_path) {
            flb_plg_debug(ctx->ins, "failed to create path for vendor file");
            continue;
        }

        if (gpu_read_line(vendor_path, vendor, sizeof(vendor)) != 0) {
            flb_plg_debug(ctx->ins, "could not read %s", vendor_path);
            continue;
        }

        flb_plg_info(ctx->ins, "Card%d vendor: %s", id, vendor);
        if (strncmp(vendor, AMD_VENDOR_ID, strlen(AMD_VENDOR_ID)) != 0) {
            flb_plg_info(ctx->ins, "Card%d is not AMD (vendor: %s)", id, vendor);
            continue;
        }

        flb_plg_info(ctx->ins, "Checking if card%d should be included", id);
        if (!should_include_card(ctx, id)) {
            flb_plg_info(ctx->ins, "Card%d excluded by filter", id);
            continue;
        }
        flb_plg_info(ctx->ins, "Card%d passed filter check", id);
        card = flb_calloc(1, sizeof(struct gpu_card));
        if (!card) {
            flb_errno();
            closedir(dir);
            flb_sds_destroy(path);
            flb_sds_destroy(vendor_path);
            free_cards(ctx);
            return -1;
        }
        card->id = id;
        card->hwmon_path = NULL;
        card->hwmon_path = find_hwmon_path(id);
        if (!card->hwmon_path) {
            flb_plg_debug(ctx->ins, "no hwmon path for card%d", id);
        }
        cfl_list_add(&card->_head, &ctx->cards);
        flb_plg_info(ctx->ins, "detected AMD GPU card%d", id);
    }
    closedir(dir);
    flb_sds_destroy(path);
    flb_sds_destroy(vendor_path);

    /* Mark that cards have been detected */
    ctx->cards_detected = 1;
    return 0;
}

int amd_gpu_read_utilization(struct in_gpu_metrics *ctx, int card_id, double *utilization)
{
    flb_sds_t path = NULL;
    uint64_t val;

    path = build_path(card_id, "gpu_busy_percent");
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to build path for gpu_busy_percent");
        return -1;
    }
    if (gpu_read_uint64(path, &val) != 0) {
        flb_plg_debug(ctx->ins, "failed to read %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(path);
    *utilization = (double) val;
    return 0;
}

int amd_gpu_read_memory_info(struct in_gpu_metrics *ctx, int card_id, uint64_t *used, uint64_t *total)
{
    flb_sds_t path = NULL;

    path = build_path(card_id, "mem_info_vram_used");
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to build path for mem_info_vram_used");
        return -1;
    }
    if (gpu_read_uint64(path, used) != 0) {
        flb_plg_debug(ctx->ins, "failed to read %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(path);

    path = build_path(card_id, "mem_info_vram_total");
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to build path for mem_info_vram_total");
        return -1;
    }
    if (gpu_read_uint64(path, total) != 0) {
        flb_plg_debug(ctx->ins, "failed to read %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(path);
    return 0;
}

static int read_clock_file(struct in_gpu_metrics *ctx, int card_id, const char *file, double *clock)
{
    flb_sds_t path = NULL;
    char line[256];
    FILE *fp;

    path = build_path(card_id, file);
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to build path for %s", file);
        return -1;
    }
    fp = fopen(path, "r");
    if (!fp) {
        flb_plg_debug(ctx->ins, "could not open %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    while (fgets(line, sizeof(line), fp)) {
        if (strchr(line, '*')) {
            double freq;
            if (sscanf(line, "%*d: %lfMhz", &freq) == 1) {
                *clock = freq;
                fclose(fp);
                flb_sds_destroy(path);
                return 0;
            }
        }
    }
    fclose(fp);
    flb_plg_debug(ctx->ins, "no active clock in %s", path);
    flb_sds_destroy(path);
    return -1;
}

static int read_power_watts(struct in_gpu_metrics *ctx, struct gpu_card *card, double *power)
{
    flb_sds_t path = NULL;

    if (!card->hwmon_path) {
        return -1;
    }
    path = flb_sds_create_size(256); /* Allocate initial buffer */
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to allocate path buffer");
        return -1;
    }
    path = flb_sds_printf(&path, "%s/power1_average", card->hwmon_path);
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to create path for power1_average");
        return -1;
    }
    if (gpu_read_double(path, 1000000.0, power) != 0) {
        flb_plg_debug(ctx->ins, "failed to read %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(path);
    return 0;
}

static int read_temp_celsius(struct in_gpu_metrics *ctx, struct gpu_card *card, double *temp)
{
    flb_sds_t path = NULL;

    if (!card->hwmon_path) {
        return -1;
    }
    path = flb_sds_create_size(256); /* Allocate initial buffer */
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to allocate path buffer");
        return -1;
    }
    path = flb_sds_printf(&path, "%s/temp1_input", card->hwmon_path);
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to create path for temp1_input");
        return -1;
    }
    if (gpu_read_double(path, 1000.0, temp) != 0) {
        flb_plg_debug(ctx->ins, "failed to read %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(path);
    return 0;
}

static int read_fan_speed(struct in_gpu_metrics *ctx, struct gpu_card *card, double *speed)
{
    flb_sds_t path = NULL;
    uint64_t val;

    if (!card->hwmon_path) {
        return -1;
    }
    path = flb_sds_create_size(256); /* Allocate initial buffer */
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to allocate path buffer");
        return -1;
    }
    path = flb_sds_printf(&path, "%s/fan1_input", card->hwmon_path);
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to create path for fan1_input");
        return -1;
    }
    if (gpu_read_uint64(path, &val) != 0) {
        flb_plg_debug(ctx->ins, "failed to read %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(path);
    *speed = (double) val;
    return 0;
}

static int read_fan_pwm(struct in_gpu_metrics *ctx, struct gpu_card *card, double *pwm)
{
    flb_sds_t path = NULL;
    uint64_t val;

    if (!card->hwmon_path) {
        return -1;
    }
    path = flb_sds_create_size(256); /* Allocate initial buffer */
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to allocate path buffer");
        return -1;
    }
    path = flb_sds_printf(&path, "%s/pwm1", card->hwmon_path);
    if (!path) {
        flb_plg_debug(ctx->ins, "failed to create path for pwm1");
        return -1;
    }
    if (gpu_read_uint64(path, &val) != 0) {
        flb_plg_debug(ctx->ins, "failed to read %s", path);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(path);
    *pwm = ((double) val * 100.0) / 255.0;
    return 0;
}

int amd_gpu_collect_metrics(struct in_gpu_metrics *ctx, struct gpu_card *card)
{
    double utilization;
    uint64_t used;
    uint64_t total;
    double clock;
    double power;
    double temp;
    double fan_speed;
    double fan_pwm;
    uint64_t ts;
    flb_sds_t card_id = NULL;

    ts = cfl_time_now();
    card_id = flb_sds_create_size(32); /* Allocate initial buffer for card ID */
    if (!card_id) {
        flb_plg_debug(ctx->ins, "failed to allocate card_id buffer");
        return -1;
    }
    card_id = flb_sds_printf(&card_id, "%d", card->id);
    if (!card_id) {
        flb_plg_debug(ctx->ins, "failed to create card_id string");
        return -1;
    }

    if (amd_gpu_read_utilization(ctx, card->id, &utilization) == 0) {
        cmt_gauge_set(ctx->g_utilization, ts, utilization, 2,
                      (char *[]) {card_id, "amd"});
    }

    if (amd_gpu_read_memory_info(ctx, card->id, &used, &total) == 0) {
        cmt_gauge_set(ctx->g_mem_used, ts, (double) used, 2,
                      (char *[]) {card_id, "amd"});
        cmt_gauge_set(ctx->g_mem_total, ts, (double) total, 2,
                      (char *[]) {card_id, "amd"});
    }

    if (read_clock_file(ctx, card->id, "pp_dpm_sclk", &clock) == 0) {
        cmt_gauge_set(ctx->g_clock, ts, clock, 3,
                      (char *[]) {card_id, "amd", "graphics"});
    }
    if (read_clock_file(ctx, card->id, "pp_dpm_mclk", &clock) == 0) {
        cmt_gauge_set(ctx->g_clock, ts, clock, 3,
                      (char *[]) {card_id, "amd", "memory"});
    }
    if (read_clock_file(ctx, card->id, "pp_dpm_socclk", &clock) == 0) {
        cmt_gauge_set(ctx->g_clock, ts, clock, 3,
                      (char *[]) {card_id, "amd", "soc"});
    }

    if (ctx->enable_power && read_power_watts(ctx, card, &power) == 0) {
        cmt_gauge_set(ctx->g_power, ts, power, 2,
                      (char *[]) {card_id, "amd"});
    }

    if (ctx->enable_temperature && read_temp_celsius(ctx, card, &temp) == 0) {
        cmt_gauge_set(ctx->g_temp, ts, temp, 2,
                      (char *[]) {card_id, "amd"});
    }

    if (read_fan_speed(ctx, card, &fan_speed) == 0) {
        cmt_gauge_set(ctx->g_fan_speed, ts, fan_speed, 2,
                      (char *[]) {card_id, "amd"});
    }

    if (read_fan_pwm(ctx, card, &fan_pwm) == 0) {
        cmt_gauge_set(ctx->g_fan_pwm, ts, fan_pwm, 2,
                      (char *[]) {card_id, "amd"});
    }

    flb_sds_destroy(card_id);
    return 0;
}

