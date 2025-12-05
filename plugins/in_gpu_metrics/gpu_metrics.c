/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log.h>
#include <cfl/cfl_time.h>

#include "gpu_metrics.h"
#include "amd_gpu.h"

static int in_gpu_collect(struct flb_input_instance *ins,
                          struct flb_config *config, void *in_context)
{
    struct cfl_list *head;
    struct gpu_card *card;
    struct in_gpu_metrics *ctx = in_context;

    cfl_list_foreach(head, &ctx->cards) {
        card = cfl_list_entry(head, struct gpu_card, _head);
        amd_gpu_collect_metrics(ctx, card);
    }

    flb_input_metrics_append(ctx->ins, NULL, 0, ctx->cmt);
    return 0;
}

static int in_gpu_init(struct flb_input_instance *ins,
                       struct flb_config *config, void *data)
{
    int ret;
    struct in_gpu_metrics *ctx;

    ctx = flb_calloc(1, sizeof(struct in_gpu_metrics));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->cards_detected = 0;
    cfl_list_init(&ctx->cards);

    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    /* defaults */
    if (!ctx->path_sysfs) {
        ctx->path_sysfs = flb_sds_create("/sys");
    }
    if (ctx->scrape_interval <= 0) {
        ctx->scrape_interval = 5;
    }

    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_free(ctx);
        return -1;
    }

    ctx->g_utilization = cmt_gauge_create(ctx->cmt, "gpu", "", "utilization_percent",
                                          "GPU utilization percent", 2,
                                          (char *[]) {"card", "vendor"});

    ctx->g_mem_used = cmt_gauge_create(ctx->cmt, "gpu", "", "memory_used_bytes",
                                       "GPU memory used in bytes", 2,
                                       (char *[]) {"card", "vendor"});

    ctx->g_mem_total = cmt_gauge_create(ctx->cmt, "gpu", "", "memory_total_bytes",
                                        "GPU total memory in bytes", 2,
                                        (char *[]) {"card", "vendor"});

    ctx->g_clock = cmt_gauge_create(ctx->cmt, "gpu", "", "clock_mhz",
                                    "GPU clock MHz", 3,
                                    (char *[]) {"card", "vendor", "type"});

    ctx->g_power = cmt_gauge_create(ctx->cmt, "gpu", "", "power_watts",
                                    "GPU power usage in watts", 2,
                                    (char *[]) {"card", "vendor"});

    ctx->g_temp = cmt_gauge_create(ctx->cmt, "gpu", "", "temperature_celsius",
                                   "GPU temperature in Celsius", 2,
                                   (char *[]) {"card", "vendor"});

    ctx->g_fan_speed = cmt_gauge_create(ctx->cmt, "gpu", "", "fan_speed_rpm",
                                        "GPU fan speed in RPM", 2,
                                        (char *[]) {"card", "vendor"});

    ctx->g_fan_pwm = cmt_gauge_create(ctx->cmt, "gpu", "", "fan_pwm_percent",
                                      "GPU fan PWM percentage", 2,
                                      (char *[]) {"card", "vendor"});

    amd_gpu_detect_cards(ctx);
    flb_input_set_context(ins, ctx);

    ret = flb_input_set_collector_time(ins, in_gpu_collect,
                                       ctx->scrape_interval, 0, config);
    if (ret < 0) {
        flb_plg_error(ins, "could not set collector");
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static void in_gpu_pause(void *data, struct flb_config *config)
{
    struct in_gpu_metrics *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_gpu_resume(void *data, struct flb_config *config)
{
    struct in_gpu_metrics *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_gpu_exit(void *data, struct flb_config *config)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct gpu_card *card;
    struct in_gpu_metrics *ctx = data;

    cfl_list_foreach_safe(head, tmp, &ctx->cards) {
        card = cfl_list_entry(head, struct gpu_card, _head);
        if (card->hwmon_path) {
            flb_sds_destroy(card->hwmon_path);
        }
        cfl_list_del(&card->_head);
        flb_free(card);
    }

    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "cards_exclude", "",
     0, FLB_TRUE, offsetof(struct in_gpu_metrics, cards_exclude),
     "Exclude GPU cards by ID. Accepts '*' for all, comma-separated IDs "
     "(e.g., '0,1,2'), or ranges (e.g., '0-2')."
    },
    {
     FLB_CONFIG_MAP_STR, "cards_include", "*",
     0, FLB_TRUE, offsetof(struct in_gpu_metrics, cards_include),
     "Include GPU cards by ID. Accepts '*' for all, comma-separated IDs "
     "(e.g., '0,1,2'), or ranges (e.g., '0-2')."
    },
    {
     FLB_CONFIG_MAP_BOOL, "enable_power", "true",
     0, FLB_TRUE, offsetof(struct in_gpu_metrics, enable_power),
     "Enable collection of GPU power consumption metrics (gpu_power_watts)."
    },
    {
     FLB_CONFIG_MAP_BOOL, "enable_temperature", "true",
     0, FLB_TRUE, offsetof(struct in_gpu_metrics, enable_temperature),
     "Enable collection of GPU temperature metrics (gpu_temperature_celsius)."
    },
    {
     FLB_CONFIG_MAP_STR, "path_sysfs", "/sys",
     0, FLB_TRUE, offsetof(struct in_gpu_metrics, path_sysfs),
     "sysfs mount point."
    },
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "5",
     0, FLB_TRUE, offsetof(struct in_gpu_metrics, scrape_interval),
     "Scrape interval to collect GPU metrics."
    },
    {0}
};

struct flb_input_plugin in_gpu_metrics_plugin = {
    .name         = "gpu_metrics",
    .description  = "GPU Metrics",
    .cb_init      = in_gpu_init,
    .cb_collect   = in_gpu_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_gpu_pause,
    .cb_resume    = in_gpu_resume,
    .cb_exit      = in_gpu_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_THREADED
};
