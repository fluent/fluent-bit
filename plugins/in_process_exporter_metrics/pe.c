/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023-2026 The Fluent Bit Authors
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

#include "pe.h"
#include "pe_config.h"

#include "pe_process.h"

static void update_metrics(struct flb_input_instance *ins, struct flb_pe *ctx)
{
    pe_process_update(ctx);
}

/*
 * Update the metrics, this function is invoked every time 'scrape_interval'
 * expires.
 */
static int cb_pe_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    struct flb_pe *ctx = in_context;

    update_metrics(ins, ctx);

    /* Append the updated metrics */
    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }

    return 0;
}

static int in_pe_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_pe *ctx;

    /* Create plugin context */
    ctx = flb_pe_config_create(in, config);
    if (!ctx) {
        flb_errno();
        return -1;
    }

    /* Initialize fds */
    ctx->coll_fd = -1;

    /* Associate context with the instance */
    flb_input_set_context(in, ctx);

    /* Create the collector */
    ret = flb_input_set_collector_time(in,
                                       cb_pe_collect,
                                       ctx->scrape_interval, 0,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not set collector for Node Exporter Metrics plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    /* Initialize process metric collectors */
    pe_process_init(ctx);

    update_metrics(in, ctx);

    return 0;
}

static int in_pe_exit(void *data, struct flb_config *config)
{
    struct flb_pe *ctx = data;

    if (!ctx) {
        return 0;
    }

    pe_process_exit(ctx);

    flb_pe_config_destroy(ctx);

    return 0;
}

static void in_pe_pause(void *data, struct flb_config *config)
{
    struct flb_pe *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_pe_resume(void *data, struct flb_config *config)
{
    struct flb_pe *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "5",
     0, FLB_TRUE, offsetof(struct flb_pe, scrape_interval),
     "scrape interval to collect metrics from the node."
    },

    {
     FLB_CONFIG_MAP_STR, "path.procfs", "/proc",
     0, FLB_TRUE, offsetof(struct flb_pe, path_procfs),
     "procfs mount point"
    },

    {
     FLB_CONFIG_MAP_STR, "process_include_pattern",  ".+",
     0, FLB_TRUE, offsetof(struct flb_pe, process_regex_include_list_text),
     "include list regular expression"
    },

    {
     FLB_CONFIG_MAP_STR, "process_exclude_pattern", NULL,
     0, FLB_TRUE, offsetof(struct flb_pe, process_regex_exclude_list_text),
     "exclude list regular expression"
    },

    {
     FLB_CONFIG_MAP_CLIST, "metrics",
     PE_DEFAULT_ENABLED_METRICS,
     0, FLB_TRUE, offsetof(struct flb_pe, metrics),
     "Comma separated list of keys to enable metrics."
    },

    /* EOF */
    {0}
};

struct flb_input_plugin in_process_exporter_metrics_plugin = {
    .name         = "process_exporter_metrics",
    .description  = "Process Exporter Metrics (Prometheus Compatible)",
    .cb_init      = in_pe_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_pe_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_pe_pause,
    .cb_resume    = in_pe_resume,
    .cb_exit      = in_pe_exit,
    .flags        = FLB_INPUT_THREADED
};
