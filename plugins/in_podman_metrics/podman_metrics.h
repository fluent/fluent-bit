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

#ifndef FLB_IN_PODMAN_METRICS_H
#define FLB_IN_PODMAN_METRICS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_jsmn.h>

#include <monkey/mk_core/mk_list.h>

#include "podman_metrics_config.h"

static int collect_container_data(struct flb_in_metrics *ctx);
static int add_container_to_list(struct flb_in_metrics *ctx, flb_sds_t id, flb_sds_t name, flb_sds_t image_name);
static int destroy_container_list(struct flb_in_metrics *ctx);

static int create_counter(struct flb_in_metrics *ctx, struct cmt_counter **counter, flb_sds_t id, flb_sds_t name, flb_sds_t image_name, flb_sds_t metric_prefix,
                          flb_sds_t *fieds, flb_sds_t metric_name, flb_sds_t description, flb_sds_t interface, uint64_t value);
static int create_gauge(struct flb_in_metrics *ctx, struct cmt_gauge **gauge, flb_sds_t id, flb_sds_t name, flb_sds_t image_name, flb_sds_t metric_prefix,
                          flb_sds_t *fields, flb_sds_t metric_name, flb_sds_t description, flb_sds_t interface, uint64_t value);
static int create_counters(struct flb_in_metrics *ctx);

static int scrape_metrics(struct flb_config *config, struct flb_in_metrics *ctx);

static int cb_metrics_collect_runtime(struct flb_input_instance *ins, struct flb_config *config, void *in_context);
static int in_metrics_init(struct flb_input_instance *in, struct flb_config *config, void *data);
static int in_metrics_exit(void *data, struct flb_config *config);
static void in_metrics_pause(void *data, struct flb_config *config);
static void in_metrics_resume(void *data, struct flb_config *config);


static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "30",
     0, FLB_TRUE, offsetof(struct flb_in_metrics, scrape_interval),
     "Scrape interval to collect the metrics of podman containers"
     "(defaults to 30s)"
    },

    {
     FLB_CONFIG_MAP_BOOL, "scrape_on_start", "false",
     0, FLB_TRUE, offsetof(struct flb_in_metrics, scrape_on_start),
     "Scrape metrics upon start, useful to avoid waiting for 'scrape_interval' "
     "for the first round of metrics."
    },
    {
     FLB_CONFIG_MAP_STR, "path.config", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_metrics, podman_config_path),
     "Path to podman config file"
    },
    {
     FLB_CONFIG_MAP_STR, "path.sysfs", SYSFS_PATH,
     0, FLB_TRUE, offsetof(struct flb_in_metrics, sysfs_path),
     "Path to sysfs subsystem directory"
    },
    {
     FLB_CONFIG_MAP_STR, "path.procfs", PROCFS_PATH,
     0, FLB_TRUE, offsetof(struct flb_in_metrics, procfs_path),
     "Path to proc subsystem directory"
    },

    /* EOF */
    {0}
};

struct flb_input_plugin in_podman_metrics_plugin = {
    .name         = "podman_metrics",
    .description  = "Podman metrics",
    .cb_init      = in_metrics_init,
    .cb_pre_run   = NULL,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_metrics_pause,
    .cb_resume    = in_metrics_resume,
    .cb_exit      = in_metrics_exit
};

#endif
