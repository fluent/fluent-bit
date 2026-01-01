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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>
#include <float.h>

/*
 * Diskstats interface references
 * ------------------------------
 * https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
 * https://www.kernel.org/doc/Documentation/iostats.txt
 *
 * From the documentation, Kernel versions and expected fields:
 *
 *   ==  ===================================
 *    1  major number
 *    2  minor mumber
 *    3  device name
 *    4  reads completed successfully
 *    5  reads merged
 *    6  sectors read
 *    7  time spent reading (ms)
 *    8  writes completed
 *    9  writes merged
 *   10  sectors written
 *   11  time spent writing (ms)
 *   12  I/Os currently in progress
 *   13  time spent doing I/Os (ms)
 *   14  weighted time spent doing I/Os (ms)
 *   ==  ===================================
 *
 *   Kernel 4.18+ appends four more fields for discard
 *   tracking putting the total at 18:
 *
 *   ==  ===================================
 *   15  discards completed successfully
 *   16  discards merged
 *   17  sectors discarded
 *   18  time spent discarding
 *   ==  ===================================
 *
 *   Kernel 5.5+ appends two more fields for flush requests:
 *
 *   ==  =====================================
 *   19  flush requests completed successfully
 *   20  time spent flushing
 *   ==  =====================================
 */

#define KNOWN_FIELDS     17
#define SECTOR_SIZE      512

struct dt_metric {
    void *metric;
    double factor;
};

static void metric_cache_set(struct flb_ne *ctx, void *metric, double factor, int *offset)
{
    int id;
    struct dt_metric *m;
    struct dt_metric **cache;

    id = *offset;

    cache = (struct dt_metric **) ctx->dt_metrics;
    m = (struct dt_metric *) &cache[id];
    m->metric = metric;
    m->factor = factor;
    (*offset)++;
}

static void metric_cache_update(struct flb_ne *ctx, int id, flb_sds_t device,
                                flb_sds_t str_val)
{
    int ret = -1;
    uint64_t ts;
    double val;
    struct dt_metric *m;
    struct dt_metric **cache;
    struct cmt_gauge *g;
    struct cmt_counter *c;

    cache = (struct dt_metric **) ctx->dt_metrics;
    m = (struct dt_metric *) &cache[id];

    ret = ne_utils_str_to_double(str_val, &val);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not represent string value '%s' for metric id '%i', "
                      "device '%s'",
                      str_val, id, device);
        return;
    }

    ts = cfl_time_now();

    if (m->factor > DBL_EPSILON) {
        val *= m->factor;
    }

    if (id == 8) {
        g = (struct cmt_gauge *) m->metric;
        ret = cmt_gauge_set(g, ts, val, 1, (char *[]) {device});
    }
    else {
        c = (struct cmt_counter *) m->metric;
        ret = cmt_counter_set(c, ts, val, 1, (char *[]) {device});
    }

    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not update metric id '%i', device '%s'",
                      id, device);
    }

}

/* Setup metrics contexts */
static int ne_diskstats_configure(struct flb_ne *ctx)
{
    int offset = 0;
    struct cmt_counter *c;
    struct cmt_gauge *g;

    /* Create cache for metrics */
    ctx->dt_metrics = flb_calloc(1, sizeof(struct dt_metric) * KNOWN_FIELDS);
    if (!ctx->dt_metrics) {
        flb_errno();
        return -1;
    }

    /* Initialize regex for skipped devices */
    ctx->dt_regex_skip_devices = flb_regex_create(ctx->dt_regex_skip_devices_text);
    if (!ctx->dt_regex_skip_devices) {
        flb_plg_error(ctx->ins,
                      "could not initialize regex pattern for ignored "
                      "devices: '%s'",
                      IGNORED_DEVICES);
        return -1;
    }

    /* node_disk_reads_completed_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "reads_completed_total",
                           "The total number of reads completed successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_reads_merged_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "reads_merged_total",
                           "The total number of reads merged.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_read_bytes_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "read_bytes_total",
                           "The total number of bytes read successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, SECTOR_SIZE, &offset);

    /* node_disk_read_time_seconds_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "read_time_seconds_total",
                           "The total number of seconds spent by all reads.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, .001, &offset);

    /* node_disk_writes_completed_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "writes_completed_total",
                           "The total number of writes completed successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_writes_merged_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "writes_merged_total",
                           "The number of writes merged.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_written_bytes_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "written_bytes_total",
                           "The total number of bytes written successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, SECTOR_SIZE, &offset);

    /* node_disk_write_time_seconds_total */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "write_time_seconds_total",
                           "This is the total number of seconds spent by all writes.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, .001, &offset);

    /* node_disk_io_now */
    g = cmt_gauge_create(ctx->cmt, "node", "disk", "io_now",
                         "The number of I/Os currently in progress.",
                         1, (char *[]) {"device"});
    if (!g) {
        return -1;
    }
    metric_cache_set(ctx, g, 0, &offset);

    /* node_disk_io_time_seconds */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "io_time_seconds_total",
                           "Total seconds spent doing I/Os.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, .001, &offset);

    /* node_disk_io_time_weighted_seconds */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "io_time_weighted_seconds_total",
                           "The weighted # of seconds spent doing I/Os.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, .001, &offset);

    /*
     * Linux Kernel >= 4.18
     * ====================
     */

    /* node_disk_discards_completed */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "discards_completed_total",
                           "The total number of discards completed successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_discards_merged */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "discards_merged_total",
                           "The total number of discards merged.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_discarded_sectors */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "discarded_sectors_total",
                           "The total number of sectors discarded successfully.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_discard_time_seconds */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "discard_time_seconds_total",
                           "This is the total number of seconds spent by all discards.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, .001, &offset);

    /*
     * Linux Kernel >= 5.5
     * ===================
     */

    /* node_disk_flush_requests */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "flush_requests_total",
                           "The total number of flush requests completed successfully",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, 0, &offset);

    /* node_disk_flush_requests_time_seconds */
    c = cmt_counter_create(ctx->cmt, "node", "disk", "flush_requests_time_seconds_total",
                           "This is the total number of seconds spent by all flush "
                           "requests.",
                           1, (char *[]) {"device"});
    if (!c) {
        return -1;
    }
    metric_cache_set(ctx, c, .001, &offset);

    return 0;
}

static flb_sds_t get_part_id(struct mk_list *list, int id)
{
    int i = 0;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, list) {
        if (i == id) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            return entry->str;
        }
        i++;
    }
    return NULL;
}

static int skip_device(struct flb_ne *ctx, flb_sds_t device)
{
    return flb_regex_match(ctx->dt_regex_skip_devices,
                           (unsigned char *) device, flb_sds_len(device));
}

static int update_stats(struct flb_ne *ctx, struct mk_list *list, int parts)
{
    int id = 0;
    flb_sds_t device;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    /* Get device name: third entry */
    device = get_part_id(list, 2);
    if (!device) {
        flb_plg_error(ctx->ins, "cannot retrieve device name");
        return -1;
    }

    /* Check if we should process or skip this device */
    if (skip_device(ctx, device)) {
        flb_plg_debug(ctx->ins, "skip device: %s", device);
        return 0;
    }

    mk_list_foreach(head, list) {
        /* Skip: major number, minor number and device name */
        if (id <= 2) {
            id++;
            continue;
        }
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* update the metric */
        metric_cache_update(ctx, id - 3, device, entry->str);
        id++;

        /* Do not process more than the known fields as of this version */
        if (id - 3 == KNOWN_FIELDS) {
            break;
        }
    }
    return 0;
}

static int diskstats_update(struct flb_ne *ctx)
{
    int ret;
    int parts;
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *line;

    mk_list_init(&list);
    mk_list_init(&split_list);

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/diskstats", &list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, ' ', -1);
        if (ret == -1) {
            continue;
        }
        parts = ret;

        update_stats(ctx, &split_list, parts);
        flb_slist_destroy(&split_list);
    }

    flb_slist_destroy(&list);
    return 0;
}

static int ne_diskstats_init(struct flb_ne *ctx)
{
    ne_diskstats_configure(ctx);
    return 0;
}

static int ne_diskstats_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;
    diskstats_update(ctx);
    return 0;
}

static int ne_diskstats_exit(struct flb_ne *ctx)
{
    flb_free(ctx->dt_metrics);
    if (ctx->dt_regex_skip_devices) {
        flb_regex_destroy(ctx->dt_regex_skip_devices);
    }
    return 0;
}

struct flb_ne_collector diskstats_collector = {
    .name = "diskstats",
    .cb_init = ne_diskstats_init,
    .cb_update = ne_diskstats_update,
    .cb_exit = ne_diskstats_exit
};
