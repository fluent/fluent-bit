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
#include "ne_filesystem.h"
#include "ne_uname.h"
#include "ne_stat_linux.h"
#include "ne_time.h"
#include "ne_loadavg.h"
#include "ne_vmstat_linux.h"
#include "ne_netdev.h"

struct flb_ne_callback {
    char *name;
    void (*func)(char *, void *, void *);
};

static int ne_update_cb(struct flb_ne *ctx, char *name);

static void update_metrics(struct flb_input_instance *ins, struct flb_ne *ctx)
{
    int ret;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    /* Update our metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);
            if (ret == FLB_TRUE) {
                ne_update_cb(ctx, entry->str);
            }
            else {
                flb_plg_warn(ctx->ins, "Unknown metrics: %s", entry->str);
            }
        }
    }
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

static void ne_cpu_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_cpu_update(ctx);
}

static void ne_cpufreq_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_cpufreq_update(ctx);
}

static void ne_meminfo_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_meminfo_update(ctx);
}

static void ne_diskstats_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_diskstats_update(ctx);
}

static void ne_filesystem_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_filesystem_update(ctx);
}

static void ne_uname_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_uname_update(ctx);
}

static void ne_stat_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_stat_update(ctx);
}

static void ne_time_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_time_update(ctx);
}

static void ne_loadavg_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_loadavg_update(ctx);
}

static void ne_vmstat_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_vmstat_update(ctx);
}

static void ne_netdev_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_netdev_update(ctx);
}

static void ne_filefd_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_filefd_update(ctx);
}

static int ne_update_cb(struct flb_ne *ctx, char *name)
{
    int ret;

    ret = flb_callback_do(ctx->callback, name, ctx, NULL);
    return ret;
}

/*
 * Callbacks Table
 */
struct flb_ne_callback ne_callbacks[] = {
    /* metrics */
    { "cpufreq", ne_cpufreq_update_cb },
    { "cpu", ne_cpu_update_cb },
    { "meminfo", ne_meminfo_update_cb },
    { "diskstats", ne_diskstats_update_cb },
    { "filesystem", ne_filesystem_update_cb },
    { "uname", ne_uname_update_cb },
    { "stat", ne_stat_update_cb },
    { "time", ne_time_update_cb },
    { "loadavg", ne_loadavg_update_cb },
    { "vmstat", ne_vmstat_update_cb },
    { "netdev", ne_netdev_update_cb },
    { "filefd", ne_filefd_update_cb },
    { 0 }
};

static int in_ne_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    int metric_idx = 0;
    struct flb_ne *ctx;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct flb_ne_callback *cb;

    /* Create plugin context */
    ctx = flb_ne_config_create(in, config);
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->callback = flb_callback_create(in->name);
    if (!ctx->callback) {
        flb_plg_error(ctx->ins, "Create callback failed");
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
    ne_filesystem_init(ctx);
    ne_uname_init(ctx);
    ne_stat_init(ctx);
    ne_time_init(ctx);
    ne_loadavg_init(ctx);
    ne_vmstat_init(ctx);
    ne_netdev_init(ctx);
    ne_filefd_init(ctx);

    /* Check enabled metrics */
        /* Update our metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);

            if (ret == FLB_FALSE) {
                if (strncmp(entry->str, "cpufreq", 7) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 0;
                }
                else if (strncmp(entry->str, "cpu", 3) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 1;
                }
                else if (strncmp(entry->str, "meminfo", 7) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 2;
                }
                else if (strncmp(entry->str, "diskstats", 9) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 3;
                }
                else if (strncmp(entry->str, "filesystem", 10) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 4;
                }
                else if (strncmp(entry->str, "uname", 5) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 5;
                }
                else if (strncmp(entry->str, "stat", 4) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 6;
                }
                else if (strncmp(entry->str, "time", 4) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 7;
                }
                else if (strncmp(entry->str, "loadavg", 7) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 8;
                }
                else if (strncmp(entry->str, "vmstat", 6) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 9;
                }
                else if (strncmp(entry->str, "netdev", 6) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 10;
                }
                else if (strncmp(entry->str, "filefd", 6) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 11;
                }
                else {
                    flb_plg_warn(ctx->ins, "Unknown metrics: %s", entry->str);
                    metric_idx = -1;
                }

                if (metric_idx >= 0) {
                    cb = &ne_callbacks[metric_idx];
                    ret = flb_callback_set(ctx->callback, cb->name, cb->func);
                    if (ret == -1) {
                        flb_plg_error(ctx->ins, "error setting up default "
                                      "callback '%s'", cb->name);
                    }
                }
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "No metrics is specified");

        return -1;
    }

    return 0;
}

static int in_ne_exit(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;

    if (!ctx) {
        return 0;
    }

    ne_diskstats_exit(ctx);
    ne_filesystem_exit(ctx);
    ne_meminfo_exit(ctx);
    ne_vmstat_exit(ctx);
    ne_netdev_exit(ctx);

    flb_ne_config_destroy(ctx);
    /* destroy callback context */
    if (ctx->callback) {
        flb_callback_destroy(ctx->callback);
    }

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
     FLB_CONFIG_MAP_CLIST, "metrics",
     "cpu,cpufreq,meminfo,diskstats,filesystem,uname,stat,time,loadavg,vmstat,netdev,filefd",
     0, FLB_TRUE, offsetof(struct flb_ne, metrics),
     "Comma separated list of keys to enable metrics."
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
    .flags        = FLB_INPUT_THREADED
};
