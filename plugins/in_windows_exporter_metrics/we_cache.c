/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2025 The Fluent Bit Authors
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

#include <float.h>

#include "we.h"
#include "we_cache.h"
#include "we_util.h"
#include "we_metric.h"
#include "we_perflib.h"

struct we_perflib_metric_source cache_metric_sources[] = {
        WE_PERFLIB_METRIC_SOURCE("async_copy_reads_total",
                                 "Async Copy Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("async_data_maps_total",
                                 "Async Data Maps/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("async_fast_reads_total",
                                 "Async Fast Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("async_mdl_reads_total",
                                 "Async MDL Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("async_pin_reads_total",
                                 "Async Pin Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("copy_read_hits_total",
                                 "Copy Read Hits %",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("copy_reads_total",
                                 "Copy Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("data_flushes_total",
                                 "Data Flushes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("data_flush_pages_total",
                                 "Data Flush Pages/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("data_map_hits_percent",
                                 "Data Map Hits %",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("data_map_pins_total",
                                 "Data Map Pins/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("data_maps_total",
                                 "Data Maps/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("dirty_pages",
                                 "Dirty Pages",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("dirty_page_threshold",
                                 "Dirty Page Threshold",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("fast_read_not_possibles_total",
                                 "Fast Read Not Possibles/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("fast_read_resource_misses_total",
                                 "Fast Read Resource Misses/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("fast_reads_total",
                                 "Fast Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("lazy_write_flushes_total",
                                 "Lazy Write Flushes/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("lazy_write_pages_total",
                                 "Lazy Write Pages/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("mdl_read_hits_total",
                                 "MDL Read Hits %",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("mdl_reads_total",
                                 "MDL Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("pin_read_hits_total",
                                 "Pin Read Hits %",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("pin_reads_total",
                                 "Pin Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("read_aheads_total",
                                 "Read Aheads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("sync_copy_reads_total",
                                 "Sync Copy Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("sync_data_maps_total",
                                 "Sync Data Maps/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("sync_fast_reads_total",
                                 "Sync Fast Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("sync_mdl_reads_total",
                                 "Sync MDL Reads/sec",
                                 NULL),

        WE_PERFLIB_METRIC_SOURCE("sync_pin_reads_total",
                                 "Sync Pin Reads/sec",
                                 NULL),

        WE_PERFLIB_TERMINATOR_SOURCE()
};

struct we_perflib_metric_spec cache_metric_specs[] =
    {
        WE_PERFLIB_COUNTER_SPEC("async_copy_reads_total",
                                "(AsyncCopyReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("async_data_maps_total",
                                "(AsyncDataMapsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("async_fast_reads_total",
                                "(AsyncFastReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("async_mdl_reads_total",
                                "(AsyncMDLReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("async_pin_reads_total",
                                "(AsyncPinReadsTotal)",
                                NULL),

        WE_PERFLIB_GAUGE_SPEC("copy_read_hits_total",
                              "(CopyReadHitsTotal)",
                              NULL),

        WE_PERFLIB_COUNTER_SPEC("copy_reads_total",
                                "(CopyReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("data_flushes_total",
                                "(DataFlushesTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("data_flush_pages_total",
                                "(DataFlushPagesTotal)",
                                NULL),

        WE_PERFLIB_GAUGE_SPEC("data_map_hits_percent",
                              "(DataMapHitsTotal)",
                              NULL),

        WE_PERFLIB_COUNTER_SPEC("data_map_pins_total",
                                "(DataMapPinsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("data_maps_total",
                                "(DataMapsTotal)",
                                NULL),

        WE_PERFLIB_GAUGE_SPEC("dirty_pages",
                              "(DirtyPages)",
                              NULL),

        WE_PERFLIB_GAUGE_SPEC("dirty_page_threshold",
                              "(DirtyPageThreshold)",
                              NULL),

        WE_PERFLIB_COUNTER_SPEC("fast_read_not_possibles_total",
                                "(FastReadNotPossiblesTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("fast_read_resource_misses_total",
                                "(FastReadResourceMissesTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("fast_reads_total",
                                "(FastReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("lazy_write_flushes_total",
                                "(LazyWriteFlushesTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("lazy_write_pages_total",
                                "(LazyWritePagesTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("mdl_read_hits_total",
                                "(MDLReadHitsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("mdl_reads_total",
                                "(MDLReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("pin_read_hits_total",
                                "(PinReadHitsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("pin_reads_total",
                                "(PinReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("read_aheads_total",
                                "(ReadAheadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("sync_copy_reads_total",
                                "(SyncCopyReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("sync_data_maps_total",
                                "(SyncDataMapsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("sync_fast_reads_total",
                                "(SyncFastReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("sync_mdl_reads_total",
                                "(SyncMDLReadsTotal)",
                                NULL),

        WE_PERFLIB_COUNTER_SPEC("sync_pin_reads_total",
                                "(SyncPinReadsTotal)",
                                NULL),

        WE_PERFLIB_TERMINATOR_SPEC()
    };


int we_cache_init(struct flb_we *ctx)
{
    int result;

    ctx->cache.operational = FLB_FALSE;

    ctx->cache.metrics = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 64, 128);

    if (ctx->cache.metrics == NULL) {
        flb_plg_error(ctx->ins, "could not create metrics hash table");

        return -1;
    }

    result = we_initialize_perflib_metric_specs(ctx->cmt,
                                                ctx->cache.metrics,
                                                "windows",
                                                "cache",
                                                &ctx->cache.metric_specs,
                                                cache_metric_specs);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize metric specs");

        return -2;
    }

    ctx->cache.query = (char *) "Cache";

    result = we_initialize_perflib_metric_sources(ctx->cache.metrics,
                                                  &ctx->cache.metric_sources,
                                                  cache_metric_sources);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not initialize metric sources");

        we_deinitialize_perflib_metric_specs(ctx->cache.metric_specs);
        flb_free(ctx->cache.metric_specs);

        return -3;
    }

    ctx->cache.operational = FLB_TRUE;

    return 0;
}

int we_cache_exit(struct flb_we *ctx)
{
    we_deinitialize_perflib_metric_sources(ctx->cache.metric_sources);
    we_deinitialize_perflib_metric_specs(ctx->cache.metric_specs);

    flb_free(ctx->cache.metric_sources);
    flb_free(ctx->cache.metric_specs);

    ctx->cache.operational = FLB_FALSE;

    return 0;
}

int we_cache_instance_hook(char *instance_name, struct flb_we *ctx)
{
    /* Cache object has only _Total instance */
    return 0;
}

int we_cache_label_prepend_hook(char                           **label_list,
                                size_t                           label_list_size,
                                size_t                          *label_count,
                                struct we_perflib_metric_source *metric_source,
                                char                            *instance_name,
                                struct we_perflib_counter       *counter)
{
    /*
     * The cache metrics do not have any labels defined in their spec,
     * so this hook must do nothing.
     */
    return 0;
}

int we_cache_update(struct flb_we *ctx)
{
    if (!ctx->cache.operational) {
        flb_plg_error(ctx->ins, "cache collector not yet in operational state");

        return -1;
    }

    return we_perflib_update_counters(ctx,
                                      ctx->cache.query,
                                      ctx->cache.metric_sources,
                                      we_cache_instance_hook,
                                      we_cache_label_prepend_hook);
}
