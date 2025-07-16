/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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
#include "we_logical_disk.h"
#include "we_util.h"
#include "we_metric.h"
#include "we_perflib.h"


struct we_perflib_metric_source logical_disk_metric_sources[] = {
        WE_PERFLIB_METRIC_SOURCE("requests_queued",
                                 "Current Disk Queue Length",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_bytes_total",
                                 "Disk Read Bytes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_total",
                                 "Disk Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_bytes_total",
                                 "Disk Write Bytes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_total",
                                 "Disk Writes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_seconds_total",
                                 "% Disk Read Time",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_seconds_total",
                                 "% Disk Write Time",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("free_megabytes",
                                 "Free Megabytes",
                                 NULL),

        /* FIXME: Prometheus windows exporter uses '% Free Space_Base' as
         * query for size_(mega)bytes metrics, but it does not work. */
        /* WE_PERFLIB_METRIC_SOURCE("size_megabytes", */
        /*                          "% Free Space_Base", */
        /*                          NULL), */

        WE_PERFLIB_METRIC_SOURCE("idle_seconds_total",
                                 "% Idle Time",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("split_ios_total",
                                 "Split IO/Sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_latency_seconds_total",
                                 "Avg. Disk sec/Read",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("write_latency_seconds_total",
                                 "Avg. Disk sec/Write",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_write_latency_seconds_total",
                                 "Avg. Disk sec/Transfer",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("avg_read_requests_queued",
                                 "Avg. Disk Read Queue Length",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("avg_write_requests_queued",
                                 "Avg. Disk Write Queue Length",
                                 NULL),

        WE_PERFLIB_TERMINATOR_SOURCE()
    };

struct we_perflib_metric_spec logical_disk_metric_specs[] = {
        WE_PERFLIB_GAUGE_SPEC("requests_queued",
                              "Number of queued requests on the disk",
                              "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_bytes_total",
                                "Number of read bytes from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_total",
                                "Number of read from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_bytes_total",
                                "Number of write bytes to the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_total",
                                "Number of write from to disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_seconds_total",
                                "Total amount of reading time from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_seconds_total",
                                "Total amount of writeing time to the disk",
                                "volume"),

        WE_PERFLIB_GAUGE_SPEC("free_megabytes",
                              "Free megabytes on the disk",
                              "volume"),

        /* WE_PERFLIB_COUNTER_SPEC("size_megabytes", */
        /*                         "Total amount of free megabytes on the disk", */
        /*                         "volume"), */

        WE_PERFLIB_COUNTER_SPEC("idle_seconds_total",
                                "Total amount of idling time on the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("split_ios_total",
                                "Total amount of split I/O operations on the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_latency_seconds_total",
                                "Average latency, in seconds, to read from the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("write_latency_seconds_total",
                                "Average latency, in seconds, to write into the disk",
                                "volume"),

        WE_PERFLIB_COUNTER_SPEC("read_write_latency_seconds_total",
                                "Average latency, in seconds, to transfer operations on the disk",
                                "volume"),

        WE_PERFLIB_GAUGE_SPEC("avg_read_requests_queued",
                              "Average number of read requests that were queued for the selected disk during the sample interval",
                              "volume"),

        WE_PERFLIB_GAUGE_SPEC("avg_write_requests_queued",
                              "Average number of write requests that were queued for the selected disk during the sample interval",
                              "volume"),

        WE_PERFLIB_TERMINATOR_SPEC()
    };


int we_logical_disk_init(struct flb_we *ctx)
{
    struct we_perflib_metric_source *metric_sources;
    int                              result;

    ctx->logical_disk.operational = FLB_FALSE;

    ctx->logical_disk.metrics = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 32, 128);

    if (ctx->logical_disk.metrics == NULL) {
        flb_plg_error(ctx->ins, "could not create metrics hash table for logical_disk metrics");

        return -1;
    }

    result = we_initialize_perflib_metric_specs(ctx->cmt,
                                                ctx->logical_disk.metrics,
                                                "windows",
                                                "logical_disk",
                                                &ctx->logical_disk.metric_specs,
                                                logical_disk_metric_specs);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize logical_disk metric specs");

        return -2;
    }

    ctx->logical_disk.query = (char *) "LogicalDisk";

    result = we_initialize_perflib_metric_sources(ctx->logical_disk.metrics,
                                                  &ctx->logical_disk.metric_sources,
                                                  logical_disk_metric_sources);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize logical_disk metric sources");

        we_deinitialize_perflib_metric_specs(ctx->logical_disk.metric_specs);
        flb_free(ctx->logical_disk.metric_specs);

        return -3;
    }

    ctx->logical_disk.operational = FLB_TRUE;

    return 0;
}

int we_logical_disk_exit(struct flb_we *ctx)
{
    we_deinitialize_perflib_metric_sources(ctx->logical_disk.metric_sources);
    we_deinitialize_perflib_metric_specs(ctx->logical_disk.metric_specs);

    flb_free(ctx->logical_disk.metric_sources);
    flb_free(ctx->logical_disk.metric_specs);

    ctx->logical_disk.operational = FLB_FALSE;

    return 0;
}

static int logical_disk_regex_match(struct flb_regex *regex, char *instance_name)
{
    if (regex == NULL) {
        return 0;
    }
    return flb_regex_match(regex, instance_name, strlen(instance_name));
}


int we_logical_disk_instance_hook(char *instance_name, struct flb_we *ctx)
{
    if (strcasestr(instance_name, "Total") != NULL) {
        return 1;
    }
    if (logical_disk_regex_match(ctx->denying_disk_regex, instance_name) ||
        !logical_disk_regex_match(ctx->allowing_disk_regex, instance_name)) {
        return 1;
    }

    return 0;
}

int we_logical_disk_label_prepend_hook(char                           **label_list,
                                       size_t                           label_list_size,
                                       size_t                          *label_count,
                                       struct we_perflib_metric_source *metric_source,
                                       char                            *instance_name,
                                       struct we_perflib_counter       *counter)
{
    if (label_count == NULL) {
        return -1;
    }

    if (*label_count >= label_list_size) {
        return -2;
    }

    label_list[(*label_count)++] = instance_name;

    return 0;
}

int we_logical_disk_update(struct flb_we *ctx)
{
    if (!ctx->logical_disk.operational) {
        flb_plg_error(ctx->ins, "logical_disk collector not yet in operational state");

        return -1;
    }

    return we_perflib_update_counters(ctx,
                                      ctx->logical_disk.query,
                                      ctx->logical_disk.metric_sources,
                                      we_logical_disk_instance_hook,
                                      we_logical_disk_label_prepend_hook);
}
