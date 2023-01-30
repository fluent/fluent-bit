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
#include "we_os.h"
#include "we_net.h"
#include "we_logical_disk.h"
#include "we_cs.h"

struct flb_we_callback {
    char *name;
    void (*func)(char *, void *, void *);
};

static int we_update_cb(struct flb_we *ctx, char *name);

static void update_metrics(struct flb_input_instance *ins, struct flb_we *ctx)
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
                we_update_cb(ctx, entry->str);
            }
            else {
                flb_plg_debug(ctx->ins, "Callback for metrics '%s' is not registered", entry->str);
            }
        }
    }
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

static void we_cpu_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_cpu_update(ctx);
}

static void we_os_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_os_update(ctx);
}

static void we_net_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_net_update(ctx);
}

static void we_logical_disk_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_logical_disk_update(ctx);
}

static void we_cs_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_cs_update(ctx);
}

static void we_wmi_thermalzone_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_wmi_thermalzone_update(ctx);
}

static void we_wmi_cpu_info_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_wmi_cpu_info_update(ctx);
}

static void we_wmi_logon_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_wmi_logon_update(ctx);
}

static void we_wmi_system_update_cb(char *name, void *p1, void *p2)
{
    struct flb_we *ctx = p1;

    we_wmi_system_update(ctx);
}

static int we_update_cb(struct flb_we *ctx, char *name)
{
    int ret;

    ret = flb_callback_do(ctx->callback, name, ctx, NULL);
    return ret;
}

/*
 * Callbacks Table
 */
struct flb_we_callback ne_callbacks[] = {
    /* metrics */
    { "cpu_info", we_wmi_cpu_info_update_cb },
    { "cpu", we_cpu_update_cb },
    { "os", we_os_update_cb },
    { "net", we_net_update_cb },
    { "logical_disk", we_logical_disk_update_cb },
    { "cs", we_cs_update_cb },
    { "thermalzone", we_wmi_thermalzone_update_cb },
    { "logon", we_wmi_logon_update_cb },
    { "system", we_wmi_system_update_cb },
    { 0 }
};

static int in_we_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int            ret;
    int metric_idx = -1;
    struct flb_we *ctx;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct flb_we_callback *cb;

    /* Create plugin context */
    ctx = flb_we_config_create(in, config);

    if (ctx == NULL) {
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

    /* Check and initialize enabled metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);

            if (ret == FLB_FALSE) {
                if (strncmp(entry->str, "cpu_info", 8) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 0;
                    /* Initialize cpu info metric collectors */
                    ret = we_wmi_cpu_info_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "cpu", 3) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 1;
                    /* Initialize cpu metric collectors */
                    ret = we_cpu_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "os", 2) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 2;
                    /* Initialize os metric collectors */
                    ret = we_os_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "net", 3) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 3;
                    /* Initialize net metric collectors */
                    ret = we_net_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "logical_disk", 12) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 4;
                    /* Initialize logical_disk metric collectors */
                    ret = we_logical_disk_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "cs", 2) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 5;
                    /* Initialize cs metric collectors */
                    ret = we_cs_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "thermalzone", 11) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 6;
                    /* Initialize thermalzone metric collectors */
                    ret = we_wmi_thermalzone_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "logon", 5) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 7;
                    /* Initialize logon metric collectors */
                    ret = we_wmi_logon_init(ctx);
                    if (ret) {
                        return -1;
                    }
                }
                else if (strncmp(entry->str, "system", 6) == 0) {
                    flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    metric_idx = 8;
                    /* Initialize system metric collectors */
                    ret = we_wmi_system_init(ctx);
                    if (ret) {
                        return -1;
                    }
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

static int in_we_exit(void *data, struct flb_config *config)
{
    int ret;
    struct flb_we* ctx = data;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    if (data == NULL) {
        return 0;
    }

        /* Teardown for callback tied up resources */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);

            if (ret == FLB_TRUE) {
                if (strncmp(entry->str, "cpu_info", 8) == 0) {
                    we_wmi_cpu_info_exit(ctx);
                }
                else if (strncmp(entry->str, "cpu", 3) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "os", 2) == 0) {
                    we_os_exit(ctx);
                }
                else if (strncmp(entry->str, "net", 3) == 0) {
                    we_net_exit(ctx);
                }
                else if (strncmp(entry->str, "logical_disk", 12) == 0) {
                    we_logical_disk_exit(ctx);
                }
                else if (strncmp(entry->str, "cs", 2) == 0) {
                    we_cs_exit(ctx);
                }
                else if (strncmp(entry->str, "thermalzone", 11) == 0) {
                    we_wmi_thermalzone_exit(ctx);
                }
                else if (strncmp(entry->str, "logon", 5) == 0) {
                    we_wmi_logon_exit(ctx);
                }
                else if (strncmp(entry->str, "system", 6) == 0) {
                    we_wmi_system_exit(ctx);
                }
                else {
                    flb_plg_warn(ctx->ins, "Unknown metrics: %s", entry->str);
                }
            }
        }
    }

    /* destroy callback context */
    if (ctx->callback) {
        flb_callback_destroy(ctx->callback);
    }

    flb_we_config_destroy(ctx);

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
    {
     FLB_CONFIG_MAP_CLIST, "metrics",
     "cpu,cpu_info,os,net,logical_disk,cs,thermalzone,logon,system",
     0, FLB_TRUE, offsetof(struct flb_we, metrics),
     "Comma separated list of keys to enable metrics."
    },
    {
     FLB_CONFIG_MAP_STR, "we.logical_disk.allow_disk_regex", "/.+/",
     0, FLB_TRUE, offsetof(struct flb_we, raw_allowing_disk),
     "Specify to be scribable regex for logical disk metrics."
    },
    {
     FLB_CONFIG_MAP_STR, "we.logical_disk.deny_disk_regex", NULL,
     0, FLB_TRUE, offsetof(struct flb_we, raw_denying_disk),
     "Specify to be denied regex for logical disk metrics."
    },
    {
     FLB_CONFIG_MAP_STR, "we.net.allow_nic_regex", "/.+/",
     0, FLB_TRUE, offsetof(struct flb_we, raw_allowing_nic),
     "Specify to be scribable regex for net metrics by name of NIC."
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
};
