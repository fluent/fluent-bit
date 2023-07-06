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
#include "ne_textfile.h"
#include "ne_systemd.h"

static int ne_timer_cpu_metrics_cb(struct flb_input_instance *ins,
                                   struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_cpu_update(ctx);

    return 0;
}

static int ne_timer_cpufreq_metrics_cb(struct flb_input_instance *ins,
                                       struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_cpufreq_update(ctx);

    return 0;
}

static int ne_timer_meminfo_metrics_cb(struct flb_input_instance *ins,
                                       struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_meminfo_update(ctx);

    return 0;
}

static int ne_timer_diskstats_metrics_cb(struct flb_input_instance *ins,
                                         struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_diskstats_update(ctx);

    return 0;
}

static int ne_timer_filesystem_metrics_cb(struct flb_input_instance *ins,
                                          struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_filesystem_update(ctx);

    return 0;
}

static int ne_timer_uname_metrics_cb(struct flb_input_instance *ins,
                                     struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_uname_update(ctx);

    return 0;
}

static int ne_timer_stat_metrics_cb(struct flb_input_instance *ins,
                                    struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_stat_update(ctx);

    return 0;
}

static int ne_timer_time_metrics_cb(struct flb_input_instance *ins,
                                    struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_time_update(ctx);

    return 0;
}

static int ne_timer_loadavg_metrics_cb(struct flb_input_instance *ins,
                                       struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_loadavg_update(ctx);

    return 0;
}

static int ne_timer_vmstat_metrics_cb(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_vmstat_update(ctx);

    return 0;
}

static int ne_timer_netdev_metrics_cb(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_netdev_update(ctx);

    return 0;
}

static int ne_timer_filefd_metrics_cb(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_filefd_update(ctx);

    return 0;
}

static int ne_timer_textfile_metrics_cb(struct flb_input_instance *ins,
                                        struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_textfile_update(ctx);

    return 0;
}

static int ne_timer_systemd_metrics_cb(struct flb_input_instance *ins,
                                       struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = in_context;

    ne_systemd_update(ctx);

    return 0;
}

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
                flb_plg_debug(ctx->ins, "Callback for metrics '%s' is not registered", entry->str);
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

static void ne_textfile_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_textfile_update(ctx);
}

static void ne_systemd_update_cb(char *name, void *p1, void *p2)
{
    struct flb_ne *ctx = p1;

    ne_systemd_update(ctx);
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
    { "textfile", ne_textfile_update_cb },
    { "systemd", ne_systemd_update_cb },
    { 0 }
};

static int in_ne_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    int metric_idx = -1;
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

    /* Initialize fds */
    ctx->coll_fd = -1;
    ctx->coll_cpu_fd = -1;
    ctx->coll_cpufreq_fd = -1;
    ctx->coll_meminfo_fd = -1;
    ctx->coll_diskstats_fd = -1;
    ctx->coll_filesystem_fd = -1;
    ctx->coll_uname_fd = -1;
    ctx->coll_stat_fd = -1;
    ctx->coll_time_fd = -1;
    ctx->coll_loadavg_fd = -1;
    ctx->coll_vmstat_fd = -1;
    ctx->coll_netdev_fd = -1;
    ctx->coll_filefd_fd = -1;
    ctx->coll_textfile_fd = -1;

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

    /* Check and initialize enabled metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);

            if (ret == FLB_FALSE) {
                if (strncmp(entry->str, "cpufreq", 7) == 0) {
                    if (ctx->cpu_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 0;
                    }
                    else if (ctx->cpufreq_scrape_interval > 0) {
                        /* Create the cpufreq collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_cpufreq_metrics_cb,
                                                           ctx->cpufreq_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set cpufreq collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_cpufreq_fd = ret;
                    }
                    ne_cpufreq_init(ctx);
                }
                else if (strncmp(entry->str, "cpu", 3) == 0) {
                    if (ctx->cpufreq_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 1;
                    }
                    else if (ctx->cpu_scrape_interval > 0) {
                        /* Create the cpu collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_cpu_metrics_cb,
                                                           ctx->cpu_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set cpu collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_cpu_fd = ret;
                    }
                    ne_cpu_init(ctx);
                }
                else if (strncmp(entry->str, "meminfo", 7) == 0) {
                    if (ctx->meminfo_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 2;
                    }
                    else if (ctx->meminfo_scrape_interval > 0) {
                        /* Create the meminfo collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_meminfo_metrics_cb,
                                                           ctx->meminfo_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set meminfo collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_meminfo_fd = ret;
                    }
                    ne_meminfo_init(ctx);
                }
                else if (strncmp(entry->str, "diskstats", 9) == 0) {
                    if (ctx->diskstats_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 3;
                    }
                    else if (ctx->diskstats_scrape_interval > 0) {
                        /* Create the diskstats collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_diskstats_metrics_cb,
                                                           ctx->diskstats_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set diskstats collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_diskstats_fd = ret;
                    }
                    ne_diskstats_init(ctx);
                }
                else if (strncmp(entry->str, "filesystem", 10) == 0) {
                    if (ctx->diskstats_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 4;
                    }
                    else if (ctx->filesystem_scrape_interval > 0) {
                        /* Create the diskstats collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_filesystem_metrics_cb,
                                                           ctx->filesystem_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set filesystem collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_filesystem_fd = ret;
                    }
                    ne_filesystem_init(ctx);
                }
                else if (strncmp(entry->str, "uname", 5) == 0) {
                    if (ctx->uname_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 5;
                    }
                    else if (ctx->uname_scrape_interval > 0) {
                        /* Create the uname collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_uname_metrics_cb,
                                                           ctx->uname_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set uname collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_uname_fd = ret;
                    }
                    ne_uname_init(ctx);
                }
                else if (strncmp(entry->str, "stat", 4) == 0) {
                    if (ctx->stat_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 6;
                    }
                    else if (ctx->stat_scrape_interval > 0) {
                        /* Create the meminfo collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_stat_metrics_cb,
                                                           ctx->stat_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set meminfo collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_stat_fd = ret;
                    }
                    ne_stat_init(ctx);
                }
                else if (strncmp(entry->str, "time", 4) == 0) {
                    if (ctx->time_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 7;
                    }
                    else if (ctx->time_scrape_interval > 0) {
                        /* Create the time collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_time_metrics_cb,
                                                           ctx->time_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set time collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_time_fd = ret;
                    }
                    ne_time_init(ctx);
                }
                else if (strncmp(entry->str, "loadavg", 7) == 0) {
                    if (ctx->loadavg_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 8;
                    }
                    else if (ctx->loadavg_scrape_interval > 0) {
                        /* Create the loadavg collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_loadavg_metrics_cb,
                                                           ctx->loadavg_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set loadavg collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_loadavg_fd = ret;
                    }
                    ne_loadavg_init(ctx);
                }
                else if (strncmp(entry->str, "vmstat", 6) == 0) {
                    if (ctx->vmstat_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 9;
                    }
                    else if (ctx->vmstat_scrape_interval > 0) {
                        /* Create the vmstat collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_vmstat_metrics_cb,
                                                           ctx->vmstat_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set vmstat collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_vmstat_fd = ret;
                    }
                    ne_vmstat_init(ctx);
                }
                else if (strncmp(entry->str, "netdev", 6) == 0) {
                    if (ctx->netdev_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 10;
                    }
                    else if (ctx->netdev_scrape_interval > 0) {
                        /* Create the netdev collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_netdev_metrics_cb,
                                                           ctx->netdev_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set netdev collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_netdev_fd = ret;
                    }
                    ne_netdev_init(ctx);
                }
                else if (strncmp(entry->str, "filefd", 6) == 0) {
                    if (ctx->filefd_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 11;
                    }
                    else if (ctx->filefd_scrape_interval > 0) {
                        /* Create the filefd collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_filefd_metrics_cb,
                                                           ctx->filefd_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set filefd collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_filefd_fd = ret;
                    }
                    ne_filefd_init(ctx);
                }
                else if (strncmp(entry->str, "textfile", 8) == 0) {
                    if (ctx->textfile_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 12;
                    }
                    else if (ctx->textfile_scrape_interval > 0) {
                        /* Create the filefd collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_textfile_metrics_cb,
                                                           ctx->textfile_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set textfile collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_textfile_fd = ret;
                    }
                    ne_textfile_init(ctx);
                }
                else if (strncmp(entry->str, "systemd", 8) == 0) {
                    if (ctx->systemd_scrape_interval == 0) {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                        metric_idx = 13;
                    }
                    else if (ctx->textfile_scrape_interval > 0) {
                        /* Create the filefd collector */
                        ret = flb_input_set_collector_time(in,
                                                           ne_timer_systemd_metrics_cb,
                                                           ctx->systemd_scrape_interval, 0,
                                                           config);
                        if (ret == -1) {
                            flb_plg_error(ctx->ins,
                                          "could not set systemd collector for Node Exporter Metrics plugin");
                            return -1;
                        }
                        ctx->coll_systemd_fd = ret;
                    }
                    ne_systemd_init(ctx);
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
    int ret;
    struct flb_ne *ctx = data;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    if (!ctx) {
        return 0;
    }

    /* Teardown for callback tied up resources */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            ret = flb_callback_exists(ctx->callback, entry->str);

            if (ret == FLB_TRUE) {
                if (strncmp(entry->str, "cpufreq", 7) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "cpu", 3) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "meminfo", 7) == 0) {
                    ne_meminfo_exit(ctx);
                }
                else if (strncmp(entry->str, "diskstats", 9) == 0) {
                    ne_diskstats_exit(ctx);
                }
                else if (strncmp(entry->str, "filesystem", 10) == 0) {
                    ne_filesystem_exit(ctx);
                }
                else if (strncmp(entry->str, "uname", 5) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "stat", 4) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "time", 4) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "loadavg", 7) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "vmstat", 6) == 0) {
                    ne_vmstat_exit(ctx);
                }
                else if (strncmp(entry->str, "netdev", 6) == 0) {
                    ne_netdev_exit(ctx);
                }
                else if (strncmp(entry->str, "filefd", 6) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "textfile", 8) == 0) {
                    /* nop */
                }
                else if (strncmp(entry->str, "systemd", 8) == 0) {
                    ne_systemd_exit(ctx);
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

    /* Teardown for timer tied up resources */
    if (ctx->coll_meminfo_fd != -1) {
        ne_meminfo_exit(ctx);
    }
    if (ctx->coll_diskstats_fd != -1) {
        ne_diskstats_exit(ctx);
    }
    if (ctx->coll_filesystem_fd != -1) {
        ne_filesystem_exit(ctx);
    }
    if (ctx->coll_vmstat_fd != -1) {
        ne_vmstat_exit(ctx);
    }
    if (ctx->coll_netdev_fd != -1) {
        ne_netdev_exit(ctx);
    }

    flb_ne_config_destroy(ctx);

    return 0;
}

static void in_ne_pause(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
    if (ctx->coll_cpu_fd != -1) {
        flb_input_collector_pause(ctx->coll_cpu_fd, ctx->ins);
    }
    if (ctx->coll_cpufreq_fd != -1) {
        flb_input_collector_pause(ctx->coll_cpufreq_fd, ctx->ins);
    }
    if (ctx->coll_meminfo_fd != -1) {
        flb_input_collector_pause(ctx->coll_meminfo_fd, ctx->ins);
    }
    if (ctx->coll_diskstats_fd != -1) {
        flb_input_collector_pause(ctx->coll_diskstats_fd, ctx->ins);
    }
    if (ctx->coll_filesystem_fd != -1) {
        flb_input_collector_pause(ctx->coll_filesystem_fd, ctx->ins);
    }
    if (ctx->coll_uname_fd != -1) {
        flb_input_collector_pause(ctx->coll_uname_fd, ctx->ins);
    }
    if (ctx->coll_stat_fd != -1) {
        flb_input_collector_pause(ctx->coll_stat_fd, ctx->ins);
    }
    if (ctx->coll_time_fd != -1) {
        flb_input_collector_pause(ctx->coll_time_fd, ctx->ins);
    }
    if (ctx->coll_loadavg_fd != -1) {
        flb_input_collector_pause(ctx->coll_loadavg_fd, ctx->ins);
    }
    if (ctx->coll_vmstat_fd != -1) {
        flb_input_collector_pause(ctx->coll_vmstat_fd, ctx->ins);
    }
    if (ctx->coll_netdev_fd != -1) {
        flb_input_collector_pause(ctx->coll_netdev_fd, ctx->ins);
    }
    if (ctx->coll_filefd_fd != -1) {
        flb_input_collector_pause(ctx->coll_filefd_fd, ctx->ins);
    }
    if (ctx->coll_textfile_fd != -1) {
        flb_input_collector_pause(ctx->coll_textfile_fd, ctx->ins);
    }
    if (ctx->coll_systemd_fd != -1) {
        flb_input_collector_pause(ctx->coll_systemd_fd, ctx->ins);
    }
}

static void in_ne_resume(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
    if (ctx->coll_cpu_fd != -1) {
        flb_input_collector_resume(ctx->coll_cpu_fd, ctx->ins);
    }
    if (ctx->coll_cpufreq_fd != -1) {
        flb_input_collector_resume(ctx->coll_cpufreq_fd, ctx->ins);
    }
    if (ctx->coll_meminfo_fd != -1) {
        flb_input_collector_resume(ctx->coll_meminfo_fd, ctx->ins);
    }
    if (ctx->coll_diskstats_fd != -1) {
        flb_input_collector_resume(ctx->coll_diskstats_fd, ctx->ins);
    }
    if (ctx->coll_filesystem_fd != -1) {
        flb_input_collector_resume(ctx->coll_filesystem_fd, ctx->ins);
    }
    if (ctx->coll_uname_fd != -1) {
        flb_input_collector_resume(ctx->coll_uname_fd, ctx->ins);
    }
    if (ctx->coll_stat_fd != -1) {
        flb_input_collector_resume(ctx->coll_stat_fd, ctx->ins);
    }
    if (ctx->coll_time_fd != -1) {
        flb_input_collector_resume(ctx->coll_time_fd, ctx->ins);
    }
    if (ctx->coll_loadavg_fd != -1) {
        flb_input_collector_resume(ctx->coll_loadavg_fd, ctx->ins);
    }
    if (ctx->coll_vmstat_fd != -1) {
        flb_input_collector_resume(ctx->coll_vmstat_fd, ctx->ins);
    }
    if (ctx->coll_netdev_fd != -1) {
        flb_input_collector_resume(ctx->coll_netdev_fd, ctx->ins);
    }
    if (ctx->coll_filefd_fd != -1) {
        flb_input_collector_resume(ctx->coll_filefd_fd, ctx->ins);
    }
    if (ctx->coll_textfile_fd != -1) {
        flb_input_collector_resume(ctx->coll_textfile_fd, ctx->ins);
    }
    if (ctx->coll_systemd_fd != -1) {
        flb_input_collector_resume(ctx->coll_systemd_fd, ctx->ins);
    }
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "5",
     0, FLB_TRUE, offsetof(struct flb_ne, scrape_interval),
     "scrape interval to collect metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.cpu.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, cpu_scrape_interval),
     "scrape interval to collect cpu metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.cpufreq.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, cpufreq_scrape_interval),
     "scrape interval to collect cpufreq metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.meminfo.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, meminfo_scrape_interval),
     "scrape interval to collect meminfo metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.diskstats.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, diskstats_scrape_interval),
     "scrape interval to collect diskstats metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.filesystem.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, filesystem_scrape_interval),
     "scrape interval to collect filesystem metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.uname.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, uname_scrape_interval),
     "scrape interval to collect uname metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.stat.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, stat_scrape_interval),
     "scrape interval to collect stat metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.time.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, time_scrape_interval),
     "scrape interval to collect time metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.loadavg.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, loadavg_scrape_interval),
     "scrape interval to collect loadavg metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.vmstat.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, vmstat_scrape_interval),
     "scrape interval to collect vmstat metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.netdev.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, netdev_scrape_interval),
     "scrape interval to collect netdev metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.filefd.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, filefd_scrape_interval),
     "scrape interval to collect filefd metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.textfile.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, textfile_scrape_interval),
     "scrape interval to collect textfile metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.systemd.scrape_interval", "0",
     0, FLB_TRUE, offsetof(struct flb_ne, systemd_scrape_interval),
     "scrape interval to collect systemd metrics from the node."
    },

    {
     FLB_CONFIG_MAP_CLIST, "metrics",
     "cpu,cpufreq,meminfo,diskstats,filesystem,uname,stat,time,loadavg,vmstat,netdev,filefd,systemd",
     0, FLB_TRUE, offsetof(struct flb_ne, metrics),
     "Comma separated list of keys to enable metrics."
    },

    {
     FLB_CONFIG_MAP_STR, "collector.textfile.path", NULL,
     0, FLB_TRUE, offsetof(struct flb_ne, path_textfile),
     "Specify file path or directory to collect textfile metrics from the node."
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

    /* Systemd specific settings */
    {
     FLB_CONFIG_MAP_BOOL, "systemd_service_restart_metrics", "false",
     0, FLB_TRUE, offsetof(struct flb_ne, systemd_include_service_restarts),
     "include systemd service restart metrics"
    },

    {
     FLB_CONFIG_MAP_BOOL, "systemd_unit_start_time_metrics", "false",
     0, FLB_TRUE, offsetof(struct flb_ne, systemd_include_unit_start_times),
     "include systemd unit start time metrics"
    },

    {
     FLB_CONFIG_MAP_BOOL, "systemd_include_service_task_metrics", "false",
     0, FLB_TRUE, offsetof(struct flb_ne, systemd_include_service_task_metrics),
     "include systemd service task metrics"
    },

    {
     FLB_CONFIG_MAP_STR, "systemd_include_pattern", NULL,
     0, FLB_TRUE, offsetof(struct flb_ne, systemd_regex_include_list_text),
     "include list regular expression"
    },

    {
     FLB_CONFIG_MAP_STR, "systemd_exclude_pattern", ".+\\.(automount|device|mount|scope|slice)",
     0, FLB_TRUE, offsetof(struct flb_ne, systemd_regex_exclude_list_text),
     "exclude list regular expression"
    },

    /* filesystem specific settings */
    {
     FLB_CONFIG_MAP_STR, "filesystem.ignore_mount_point_regex", IGNORED_MOUNT_POINTS,
     0, FLB_TRUE, offsetof(struct flb_ne, fs_regex_ingore_mount_point_text),
     "ignore regular expression for mount points"
    },

    {
     FLB_CONFIG_MAP_STR, "filesystem.ignore_filesystem_type_regex", IGNORED_FS_TYPES,
     0, FLB_TRUE, offsetof(struct flb_ne, fs_regex_ingore_filesystem_type_text),
     "ignore regular expression for filesystem types"
    },

    /* diskstats specific settings */
    {
     FLB_CONFIG_MAP_STR, "diskstats.ignore_device_regex", IGNORED_DEVICES,
     0, FLB_TRUE, offsetof(struct flb_ne, dt_regex_skip_devices_text),
     "ignore regular expression for disk devices"
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
