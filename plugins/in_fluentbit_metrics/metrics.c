/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_metrics_exporter.h>

struct flb_in_metrics {
    int coll_fd;
    int scrape_interval;
    struct flb_input_instance *ins;
};

/*
 * Update the metrics, this function is invoked every time 'scrape_interval'
 * expires.
 */
static int cb_metrics_collect(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    int ret;
    struct cmt *cmt;
    struct flb_in_metrics *ctx = in_context;

    cmt = flb_me_get_cmetrics(config);
    if (!cmt) {
        flb_plg_error(ins, "could not scrape metrics");
        return 0;
    }

    /* Append the updated metrics */
    ret = flb_input_metrics_append(ctx->ins, NULL, 0, cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }
    cmt_destroy(cmt);

    return 0;
}

static int in_metrics_init(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_metrics *ctx;

    /* Create plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_in_metrics));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Associate context with the instance */
    flb_input_set_context(in, ctx);

    /* Create the collector */
    ret = flb_input_set_collector_time(in,
                                       cb_metrics_collect,
                                       ctx->scrape_interval, 0,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not set collector for Fluent Bit metrics plugin");
        return -1;
    }
    ctx->coll_fd = ret;
    return 0;
}

static int in_metrics_exit(void *data, struct flb_config *config)
{
    struct flb_in_metrics *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

static void in_metrics_pause(void *data, struct flb_config *config)
{
    struct flb_in_metrics *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_metrics_resume(void *data, struct flb_config *config)
{
    struct flb_in_metrics *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "2",
     0, FLB_TRUE, offsetof(struct flb_in_metrics, scrape_interval),
     "scrape interval to collect the internal metrics of Fluent Bit."
    },

    /* EOF */
    {0}
};

struct flb_input_plugin in_fluentbit_metrics_plugin = {
    .name         = "fluentbit_metrics",
    .description  = "Fluent Bit internal metrics",
    .cb_init      = in_metrics_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_metrics_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_metrics_pause,
    .cb_resume    = in_metrics_resume,
    .cb_exit      = in_metrics_exit,
    .event_type   = FLB_INPUT_METRICS
};
