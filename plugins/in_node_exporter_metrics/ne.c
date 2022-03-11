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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "ne.h"
#include "ne_config.h"
#include "ne_filefd_linux.h"

/* collectors */
#include "ne_cpu.h"
#include "ne_cpufreq.h"
#include "ne_meminfo.h"
#include "ne_diskstats.h"
#include "ne_uname.h"
#include "ne_stat_linux.h"
#include "ne_time.h"
#include "ne_loadavg.h"
#include "ne_vmstat_linux.h"
#include "ne_netdev.h"

static void update_metrics(struct flb_input_instance *ins, struct flb_ne *ctx)
{
    /* Update our metrics */
    ne_cpu_update(ctx);
    ne_cpufreq_update(ctx);
    ne_meminfo_update(ctx);
    ne_diskstats_update(ctx);
    ne_uname_update(ctx);
    ne_stat_update(ctx);
    ne_time_update(ctx);
    ne_loadavg_update(ctx);
    ne_vmstat_update(ctx);
    ne_netdev_update(ctx);
    ne_filefd_update(ctx);
}

/*
 * Update the metrics, this function is invoked every time 'scrape_interval'
 * expires.
 */
static int cb_ne_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    struct flb_ne *ctx = in_context;

    update_metrics(ins, ctx);

    /* Append the updated metrics */
    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }

    return 0;
}

static int in_ne_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_ne *ctx;

    /* Create plugin context */
    ctx = flb_ne_config_create(in, config);
    if (!ctx) {
        flb_errno();
        return -1;
    }

    /* Associate context with the instance */
    flb_input_set_context(in, ctx);

    /* Create the collector */
    ret = flb_input_set_collector_time(in,
                                       cb_ne_collect,
                                       ctx->scrape_interval, 0,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not set collector for Node Exporter Metrics plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    /* Initialize node metric collectors */
    ne_cpu_init(ctx);
    ne_cpufreq_init(ctx);
    ne_meminfo_init(ctx);
    ne_diskstats_init(ctx);
    ne_uname_init(ctx);
    ne_stat_init(ctx);
    ne_time_init(ctx);
    ne_loadavg_init(ctx);
    ne_vmstat_init(ctx);
    ne_netdev_init(ctx);
    ne_filefd_init(ctx);

    return 0;
}

static int in_ne_exit(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;

    if (!ctx) {
        return 0;
    }

    ne_diskstats_exit(ctx);
    ne_meminfo_exit(ctx);
    ne_vmstat_exit(ctx);
    ne_netdev_exit(ctx);

    flb_ne_config_destroy(ctx);
    return 0;
}

static void in_ne_pause(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_ne_resume(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "5",
     0, FLB_TRUE, offsetof(struct flb_ne, scrape_interval),
     "scrape interval to collect metrics from the node."
    },

    {
     FLB_CONFIG_MAP_STR, "path.procfs", "/proc",
     0, FLB_TRUE, offsetof(struct flb_ne, path_procfs),
     "procfs mount point"
    },

    {
     FLB_CONFIG_MAP_STR, "path.sysfs", "/sys",
     0, FLB_TRUE, offsetof(struct flb_ne, path_sysfs),
     "sysfs mount point"
    },

    /* EOF */
    {0}
};

struct flb_input_plugin in_node_exporter_metrics_plugin = {
    .name         = "node_exporter_metrics",
    .description  = "Node Exporter Metrics (Prometheus Compatible)",
    .cb_init      = in_ne_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_ne_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_ne_pause,
    .cb_resume    = in_ne_resume,
    .cb_exit      = in_ne_exit,
    .event_type   = FLB_INPUT_METRICS
};
