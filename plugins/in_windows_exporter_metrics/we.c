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
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_wmi.h"
#include "we_config.h"

/* collectors */
#include "we_cpu.h"

static void update_metrics(struct flb_input_instance *ins, struct flb_we *ctx)
{
    struct mk_list *callback_iterator;
    collector_cb    callback;
    int             result;

/*
    mk_list_foreach(callback_iterator, &ctx->collectors) {
        callback = mk_list_entry(callback_iterator, collector_cb, _head);

        result = callback(ctx);

        if (callback) {
            flb_plg_error(ins, "collector failed with code %d", result);
        }
    }
*/

    /* Update our metrics */
    we_cpu_update(ctx);
}

/*
 * Update the metrics, this function is invoked every time 'scrape_interval'
 * expires.
 */
static int cb_we_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int            ret;
    struct flb_we *ctx;

    ctx = in_context;

    update_metrics(ins, ctx);

    /* Append the updated metrics */
    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);

    if (ret) {
        flb_plg_error(ins, "could not append metrics");
    }

    return 0;
}

static int in_we_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int            ret;
    struct flb_we *ctx;

    /* Create plugin context */
    ctx = flb_we_config_create(in, config);

    if (ctx == NULL) {
        flb_errno();

        return -1;
    }

    /* Associate context with the instance */
    flb_input_set_context(in, ctx);

    ctx->windows_version = we_get_windows_version();

    if (ctx->windows_version == 0) {
        flb_plg_error(in, "could not get windows version");

        return -1;
    }


    ret = we_perflib_init(ctx);

    if (ret) {
        flb_plg_error(in, "could not initialize PERFLIB");
        return -1;
    }

    ret = we_wmi_init(ctx);

    if (ret) {
        flb_plg_error(in, "could not initialize WMI");

        return -1;
    }

    /*
    {
        struct mk_list *head;
        struct flb_config_map_val *mv;
        fflush(stdout);
        flb_config_map_foreach(head, mv, ctx->collectors) {
            if (!strncasecmp(mv->val.str, "cpu")) {
                ctx->collectors
            }
            printf("[%s]\n", mv->val.str);
        }

        printf("%p\n", ctx->collectors);
        exit(0);
    }
    */

    /* Create the collector */
    ret = flb_input_set_collector_time(in,
                                       cb_we_collect,
                                       ctx->scrape_interval, 0,
                                       config);

    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not set collector for "
                      "Windows Exporter Metrics plugin");
        return -1;
    }

    ctx->coll_fd = ret;

    /* Initialize node metric collectors */
    ret = we_cpu_init(ctx);

    if (ret) {
        return -1;
    }

    return 0;
}

static int in_we_exit(void *data, struct flb_config *config)
{
    if (data == NULL) {
        return 0;
    }

    flb_we_config_destroy((struct flb_we *) data);

    return 0;
}

static void in_we_pause(void *data, struct flb_config *config)
{
    struct flb_we *ctx;

    ctx = (struct flb_we *) data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_we_resume(void *data, struct flb_config *config)
{
    struct flb_we *ctx;

    ctx = (struct flb_we *) data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "1",
     0, FLB_TRUE, offsetof(struct flb_we, scrape_interval),
     "scrape interval to collect metrics from the node."
    },
    {
     FLB_CONFIG_MAP_STR, "enable_collector", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_we, collectors),
     "Collector to enable."
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_windows_exporter_metrics_plugin = {
    .name         = "windows_exporter_metrics",
    .description  = "Windows Exporter Metrics (Prometheus Compatible)",
    .cb_init      = in_we_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_we_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_we_pause,
    .cb_resume    = in_we_resume,
    .cb_exit      = in_we_exit,
    .event_type   = FLB_INPUT_METRICS
};
