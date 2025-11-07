/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include "ne_filefd.h"

/* collectors */
#include "ne_cpu.h"
#include "ne_cpufreq.h"
#include "ne_meminfo.h"
#include "ne_diskstats.h"
#include "ne_filesystem.h"
#include "ne_uname.h"
#include "ne_stat.h"
#include "ne_time.h"
#include "ne_loadavg.h"
#include "ne_vmstat.h"
#include "ne_netdev.h"
#include "ne_netstat.h"
#include "ne_sockstat.h"
#include "ne_textfile.h"
#include "ne_systemd.h"
#include "ne_processes.h"
#include "ne_nvme.h"
#include "ne_thermalzone.h"
#include "ne_hwmon.h"

/*
 * Update the metrics, this function is invoked every time 'scrape_interval'
 * expires.
 */
static int cb_ne_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int ret;
    struct flb_ne *ctx = in_context;

    /* Append the updated metrics */
    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }

    return 0;
}

static int collectors_common_init(struct flb_ne_collector *coll)
{
    if (coll == NULL) {
        return -1;
    }
    coll->coll_fd = -1;
    coll->interval = 0;
    coll->activated = FLB_FALSE;

    return 0;
}

static int get_interval_property(struct flb_ne *ctx, flb_sds_t name)
{
    flb_sds_t interval_conf_name;
    size_t conf_len = 1024;
    const char *interval_str;
    int ret;
    int interval;

    interval_conf_name = flb_sds_create_size(conf_len);
    if (interval_conf_name == NULL) {
        flb_errno();
        return -1;
    }
    ret = flb_sds_snprintf(&interval_conf_name, conf_len, "collector.%s.scrape_interval", name);
    if (ret < 0) {
        flb_errno();
        flb_sds_destroy(interval_conf_name);
        return -1;
    }
    else if (ret > conf_len) {
        flb_plg_error(ctx->ins, "buffer is small for %s interval config", name);
        flb_sds_destroy(interval_conf_name);
        return -1;
    }

    interval_str = flb_input_get_property(interval_conf_name, ctx->ins);
    if (interval_str == NULL) {
        interval = ctx->scrape_interval;
    }
    else {
        interval = atoi(interval_str);
        if (interval == 0) {
            interval = ctx->scrape_interval;
        }
    }
    flb_sds_destroy(interval_conf_name);

    return interval;
}

static int activate_collector(struct flb_ne *ctx, struct flb_config *config,
                              struct flb_ne_collector *coll, flb_sds_t name)
{
    int interval;
    int ret;

    if (coll == NULL) {
        return -1;
    }
    if (coll->activated == FLB_TRUE) {
        flb_plg_warn(ctx->ins, "%s is already activated", name);
        return 0;
    }
    if (coll->cb_init == NULL) {
        flb_plg_warn(ctx->ins, "%s is not supported", name);
        return 0;
    }

    if (coll->cb_update) {
        interval = get_interval_property(ctx, name);
        if (interval < 0) {
            return -1;
        }
        ret = flb_input_set_collector_time(ctx->ins,
                                           coll->cb_update,
                                           interval, 0, config);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "flb_input_set_collector_time failed");
            return -1;
        }
        coll->coll_fd = ret;
    }

    ret = coll->cb_init(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "%s init failed", name);
        return -1;
    }
    coll->activated = FLB_TRUE;

    if (coll->cb_update) {
        coll->cb_update(ctx->ins, config, ctx);
    }

    return 0;
}

static int in_ne_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_ne *ctx;
    struct mk_list *head;
    struct mk_list *coll_head;
    struct flb_ne_collector *coll;
    struct flb_slist_entry *entry;

    /* Create plugin context */
    ctx = flb_ne_config_create(in, config);
    if (!ctx) {
        flb_errno();
        return -1;
    }

    mk_list_init(&ctx->collectors);
    mk_list_add(&cpu_collector._head, &ctx->collectors);
    mk_list_add(&cpufreq_collector._head, &ctx->collectors);
    mk_list_add(&meminfo_collector._head, &ctx->collectors);
    mk_list_add(&diskstats_collector._head, &ctx->collectors);
    mk_list_add(&filesystem_collector._head, &ctx->collectors);
    mk_list_add(&uname_collector._head, &ctx->collectors);
    mk_list_add(&stat_collector._head, &ctx->collectors);
    mk_list_add(&time_collector._head, &ctx->collectors);
    mk_list_add(&loadavg_collector._head, &ctx->collectors);
    mk_list_add(&vmstat_collector._head, &ctx->collectors);
    mk_list_add(&netdev_collector._head, &ctx->collectors);
    mk_list_add(&netstat_collector._head, &ctx->collectors);
    mk_list_add(&sockstat_collector._head, &ctx->collectors);
    mk_list_add(&filefd_collector._head, &ctx->collectors);
    mk_list_add(&textfile_collector._head, &ctx->collectors);
    mk_list_add(&systemd_collector._head, &ctx->collectors);
    mk_list_add(&processes_collector._head, &ctx->collectors);
    mk_list_add(&nvme_collector._head, &ctx->collectors);
    mk_list_add(&thermalzone_collector._head, &ctx->collectors);
    mk_list_add(&hwmon_collector._head, &ctx->collectors);

    mk_list_foreach(head, &ctx->collectors) {
        coll = mk_list_entry(head, struct flb_ne_collector, _head);
        collectors_common_init(coll);
    }

    /* Initialize fds */
    ctx->coll_fd = -1;

    /* Associate context with the instance */
    flb_input_set_context(in, ctx);

    /* Check and initialize enabled metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);

            mk_list_foreach(coll_head, &ctx->collectors) {
                coll = mk_list_entry(coll_head, struct flb_ne_collector, _head);
                if (coll->activated == FLB_FALSE &&
                    flb_sds_len(entry->str) == strlen(coll->name) &&
                    strncmp(entry->str, coll->name, strlen(coll->name)) == 0) {
                    ret = activate_collector(ctx, config, coll, entry->str);
                    if (ret < 0) {
                        flb_plg_error(ctx->ins,
                                      "could not set %s collector for Node Exporter Metrics plugin", entry->str);
                    }
                    else {
                        flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
                    }
                    break;
                }
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "No metrics is specified");

        return -1;
    }

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

    return 0;
}

static int in_ne_exit(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;
    struct mk_list *coll_head;
    struct flb_ne_collector *coll;

    if (!ctx) {
        return 0;
    }

    mk_list_foreach(coll_head, &ctx->collectors) {
        coll = mk_list_entry(coll_head, struct flb_ne_collector, _head);
        if (coll->activated == FLB_TRUE && coll->cb_exit) {
            coll->cb_exit(ctx);
        }
    }

    /* Teardown for timer tied up resources */

    flb_ne_config_destroy(ctx);

    return 0;
}

static void in_ne_pause(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;
    struct flb_ne_collector *coll;
    struct mk_list *head;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);

    mk_list_foreach(head, &ctx->collectors) {
        coll = mk_list_entry(head, struct flb_ne_collector, _head);
        if (coll->activated == FLB_FALSE) {
            continue;
        }
        flb_input_collector_pause(coll->coll_fd, ctx->ins);
    }
}

static void in_ne_resume(void *data, struct flb_config *config)
{
    struct flb_ne *ctx = data;
    struct flb_ne_collector *coll;
    struct mk_list *head;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
    mk_list_foreach(head, &ctx->collectors) {
        coll = mk_list_entry(head, struct flb_ne_collector, _head);
        if (coll->activated == FLB_FALSE) {
            continue;
        }
        flb_input_collector_resume(coll->coll_fd, ctx->ins);
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
     0, FLB_FALSE, 0,
     "scrape interval to collect cpu metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.cpufreq.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect cpufreq metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.meminfo.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect meminfo metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.diskstats.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect diskstats metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.filesystem.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect filesystem metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.uname.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect uname metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.stat.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect stat metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.time.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect time metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.loadavg.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect loadavg metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.vmstat.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect vmstat metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.netdev.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect netdev metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.netstat.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect netstat metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.sockstat.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect sockstat metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.filefd.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect filefd metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.textfile.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect textfile metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.systemd.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect systemd metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.processes.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect processes metrics from the node."
    },
    {
     FLB_CONFIG_MAP_TIME, "collector.thermalzone.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect thermal zone metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.nvme.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect nvme metrics from the node."
    },

    {
     FLB_CONFIG_MAP_TIME, "collector.hwmon.scrape_interval", "0",
     0, FLB_FALSE, 0,
     "scrape interval to collect hwmon metrics from the node."
    },

    {
     FLB_CONFIG_MAP_CLIST, "metrics",
     NE_DEFAULT_ENABLED_METRICS,
     0, FLB_TRUE, offsetof(struct flb_ne, metrics),
     "Comma separated list of keys to enable metrics."
    },

    {
     FLB_CONFIG_MAP_STR, "collector.textfile.path", NULL,
     0, FLB_TRUE, offsetof(struct flb_ne, path_textfile),
     "Specify file path or directory to collect textfile metrics from the node."
    },

    {
     FLB_CONFIG_MAP_STR, "path.rootfs", "/",
     0, FLB_TRUE, offsetof(struct flb_ne, path_rootfs),
     "rootfs mount point"
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

    /* hwmon specific settings */
    {
     FLB_CONFIG_MAP_STR, "collector.hwmon.chip-include", NULL,
     0, FLB_TRUE, offsetof(struct flb_ne, hwmon_chip_regex_include_text),
     "regex of chips to include"
    },

    {
     FLB_CONFIG_MAP_STR, "collector.hwmon.chip-exclude", NULL,
     0, FLB_TRUE, offsetof(struct flb_ne, hwmon_chip_regex_exclude_text),
     "regex of chips to exclude"
    },

    {
     FLB_CONFIG_MAP_STR, "collector.hwmon.sensor-include", NULL,
     0, FLB_TRUE, offsetof(struct flb_ne, hwmon_sensor_regex_include_text),
     "regex of sensors to include"
    },

    {
     FLB_CONFIG_MAP_STR, "collector.hwmon.sensor-exclude", NULL,
     0, FLB_TRUE, offsetof(struct flb_ne, hwmon_sensor_regex_exclude_text),
     "regex of sensors to exclude"
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
