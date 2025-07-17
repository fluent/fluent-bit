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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>
#include <cfl/cfl_time.h>

#include "dedup.h"

static void update_rocksdb_metrics(struct dedup_ctx *ctx)
{
    uint64_t ts;
    char *processor_name;
    uint64_t disk_size = 0;
    uint64_t live_data_size = 0;

    if (!ctx || !ctx->dedup || !ctx->cmt) {
        return;
    }

    ts = cfl_time_now();
    processor_name = (char *)flb_processor_instance_get_name(ctx->ins);

    /* Get RocksDB metrics directly */
    rocksdb_property_int(ctx->dedup->db, "rocksdb.total-sst-files-size", &disk_size);
    rocksdb_property_int(ctx->dedup->db, "rocksdb.estimate-live-data-size", &live_data_size);

    /* Update gauges */
    if (ctx->cmt_disk_size_bytes) {
        cmt_gauge_set(ctx->cmt_disk_size_bytes, ts, disk_size,
                     1, (char *[]) {processor_name});
    }

    if (ctx->cmt_live_data_size_bytes) {
        cmt_gauge_set(ctx->cmt_live_data_size_bytes, ts, live_data_size,
                     1, (char *[]) {processor_name});
    }
}

static void cb_dedup_compact(struct flb_config *config, void *data)
{
    struct dedup_ctx *ctx = data;
    uint64_t ts;
    char *processor_name;

    if (ctx->dedup) {
        flb_plg_debug(ctx->ins, "running periodic compaction");
        flb_record_dedup_compact(ctx->dedup);

        /* Update compaction counter */
        if (ctx->cmt_compactions) {
            ts = cfl_time_now();
            processor_name = (char *)flb_processor_instance_get_name(ctx->ins);
            cmt_counter_inc(ctx->cmt_compactions, ts, 1, (char *[]) {processor_name});
        }

        /* Update RocksDB metrics after compaction */
        update_rocksdb_metrics(ctx);
    }
}

static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    int ret;
    char dedup_path[2048];
    struct dedup_ctx *ctx;
    struct flb_record_dedup_options dedup_opts;
    struct mk_list *head;
    struct flb_kv *new_kv;

    ctx = flb_calloc(1, sizeof(struct dedup_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;
    ctx->config = config;

    /* Set defaults */
    ctx->ttl = 3600; /* 1 hour */
    ctx->cache_size = 100 * 1024 * 1024; /* 100MB */
    ctx->write_buffer_size = 64 * 1024 * 1024; /* 64MB */
    ctx->compact_interval = 300; /* 5 minutes */

    /* Load config values - this populates ignore_fields and ignore_field_patterns */
    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Build deduplication path */
    if (config->storage_path) {
        snprintf(dedup_path, sizeof(dedup_path) - 1, "%s/dedup/processor.%p",
                 config->storage_path, ins);
    }
    else {
        snprintf(dedup_path, sizeof(dedup_path) - 1, "/tmp/flb-storage/dedup/processor.%p",
                 ins);
    }

    /* Create parent directories if they don't exist */
    if (flb_utils_mkdir(dedup_path, 0755) != 0) {
        flb_plg_error(ins, "failed to create dedup directory: %s", dedup_path);
        flb_free(ctx);
        return -1;
    }

    /* Process ignore_fields and ignore_field_patterns if provided */
    struct mk_list processed_ignore_fields;
    struct mk_list processed_ignore_patterns;
    mk_list_init(&processed_ignore_fields);
    mk_list_init(&processed_ignore_patterns);

    /* Remove our properties from the instance properties list to avoid double-free */
    struct mk_list *tmp_head;
    struct flb_kv *prop_kv;
    mk_list_foreach_safe(head, tmp_head, &ins->properties) {
        prop_kv = mk_list_entry(head, struct flb_kv, _head);
        if ((strcasecmp(prop_kv->key, "ignore_fields") == 0 ||
             strcasecmp(prop_kv->key, "ignore_regexes") == 0) && prop_kv->val) {
            /* Create our own copy */
            if (strcasecmp(prop_kv->key, "ignore_fields") == 0) {
                new_kv = flb_kv_item_create(&processed_ignore_fields, prop_kv->val, NULL);
                if (!new_kv) {
                    flb_plg_error(ins, "failed to add ignore field: %s", prop_kv->val);
                }
            } else {
                new_kv = flb_kv_item_create(&processed_ignore_patterns, prop_kv->val, NULL);
                if (!new_kv) {
                    flb_plg_error(ins, "failed to add ignore regex: %s", prop_kv->val);
                }
            }
            /* Remove from properties list */
            mk_list_del(&prop_kv->_head);
            /* We can't free it - it was allocated by YAML parser */
        }
    }

    /* Initialize dedup options */
    flb_record_dedup_options_default(&dedup_opts);
    dedup_opts.ttl = ctx->ttl;
    dedup_opts.cache_size = ctx->cache_size;
    dedup_opts.write_buffer_size = ctx->write_buffer_size;
    dedup_opts.compact_interval = ctx->compact_interval;
    dedup_opts.ignore_fields = &processed_ignore_fields;
    dedup_opts.ignore_field_patterns = &processed_ignore_patterns;

    /* Create deduplication context */
    ctx->dedup = flb_record_dedup_context_create(dedup_path, &dedup_opts);
    if (!ctx->dedup) {
        flb_plg_error(ins, "failed to initialize deduplication");
        flb_kv_release(&processed_ignore_fields);
        flb_kv_release(&processed_ignore_patterns);
        flb_free(ctx);
        return -1;
    }

    /* Create CMetrics context */
    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(ins, "failed to create cmetrics context");
        flb_record_dedup_destroy(ctx->dedup);
        flb_kv_release(&processed_ignore_fields);
        flb_kv_release(&processed_ignore_patterns);
        flb_free(ctx);
        return -1;
    }

    /* Create counters */
    ctx->cmt_records_processed = cmt_counter_create(ctx->cmt,
                                                   "fluentbit", "processor", "dedup_records_processed_total",
                                                   "Total number of records processed by deduplication",
                                                   1, (char *[]) {"name"});

    ctx->cmt_records_removed = cmt_counter_create(ctx->cmt,
                                                 "fluentbit", "processor", "dedup_records_removed_total",
                                                 "Total number of duplicate records removed",
                                                 1, (char *[]) {"name"});

    ctx->cmt_records_kept = cmt_counter_create(ctx->cmt,
                                              "fluentbit", "processor", "dedup_records_kept_total",
                                              "Total number of unique records kept",
                                              1, (char *[]) {"name"});

    ctx->cmt_compactions = cmt_counter_create(ctx->cmt,
                                             "fluentbit", "processor", "dedup_compactions_total",
                                             "Total number of database compactions performed",
                                             1, (char *[]) {"name"});

    ctx->cmt_disk_size_bytes = cmt_gauge_create(ctx->cmt,
                                               "fluentbit", "processor", "dedup_disk_size_bytes",
                                               "Total size of SST files on disk in bytes",
                                               1, (char *[]) {"name"});

    ctx->cmt_live_data_size_bytes = cmt_gauge_create(ctx->cmt,
                                                    "fluentbit", "processor", "dedup_live_data_size_bytes",
                                                    "Estimated live data size in bytes",
                                                    1, (char *[]) {"name"});

    /* Schedule periodic compaction */
    ret = flb_sched_timer_cb_create(config->sched, FLB_SCHED_TIMER_CB_PERM,
                                    ctx->compact_interval * 1000, /* ms */
                                    cb_dedup_compact, ctx, &ctx->timer);
    if (ret == -1) {
        flb_plg_error(ins, "failed to schedule compaction timer");
    }
    else {
        ctx->coll_fd = ret;
    }

    /* Clean up our processed lists */
    flb_kv_release(&processed_ignore_fields);
    flb_kv_release(&processed_ignore_patterns);

    /* Set context */
    flb_processor_instance_set_context(ins, ctx);

    /* Set metrics context in instance */
    ins->cmt = ctx->cmt;

    /* Update RocksDB metrics after initialization */
    update_rocksdb_metrics(ctx);

    flb_plg_info(ins, "deduplication initialized at %s (ttl=%ds, cache=%zu, write_buffer=%zu)",
                 dedup_path, ctx->ttl, ctx->cache_size, ctx->write_buffer_size);

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    struct dedup_ctx *ctx = data;

    if (!ctx) {
        return FLB_PROCESSOR_SUCCESS;
    }

    /* Destroy scheduler */
    if (ctx->timer) {
        flb_sched_timer_cb_destroy(ctx->timer);
    }

    /* Destroy dedup context */
    if (ctx->dedup) {
        flb_record_dedup_destroy(ctx->dedup);
    }

    /* Note: cmt context is destroyed by the processor framework, don't destroy it here */

    /* Lists are managed by the framework */

    flb_free(ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data,
                           const char *tag,
                           int tag_len)
{
    struct dedup_ctx *ctx;
    struct flb_mp_chunk_cobj *chunk_cobj;
    struct flb_mp_chunk_record *record;
    size_t removed_count = 0;
    size_t kept_count = 0;
    size_t total_count = 0;
    uint64_t ts;
    char *processor_name;

    ctx = (struct dedup_ctx *) ins->context;
    if (!ctx) {
        return FLB_PROCESSOR_FAILURE;
    }

    chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;
    processor_name = (char *)flb_processor_instance_get_name(ins);
    ts = cfl_time_now();

    /* Iterate through records and remove duplicates */
    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {
        total_count++;

        /* Check if record is duplicate before any other operations */
        int is_duplicate = flb_record_dedup_exists(ctx->dedup, record);

        if (is_duplicate) {
            /* Duplicate - remove it */
            flb_mp_chunk_cobj_record_destroy(chunk_cobj, record);
            removed_count++;
        }
        else {
            /* Unique - add to database before moving to next record */
            flb_record_dedup_add(ctx->dedup, record);
            kept_count++;
        }
    }

    /* Update metrics */
    if (ctx->cmt_records_processed) {
        cmt_counter_add(ctx->cmt_records_processed, ts, total_count,
                       1, (char *[]) {processor_name});
    }

    if (ctx->cmt_records_removed && removed_count > 0) {
        cmt_counter_add(ctx->cmt_records_removed, ts, removed_count,
                       1, (char *[]) {processor_name});
    }

    if (ctx->cmt_records_kept && kept_count > 0) {
        cmt_counter_add(ctx->cmt_records_kept, ts, kept_count,
                       1, (char *[]) {processor_name});
    }

    if (removed_count > 0) {
        flb_plg_debug(ins, "removed %zu duplicate records out of %zu total",
                     removed_count, total_count);
    }

    /* Update RocksDB metrics after processing */
    update_rocksdb_metrics(ctx);

    return FLB_PROCESSOR_SUCCESS;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_TIME, "ttl", "3600s",
        0, FLB_TRUE, offsetof(struct dedup_ctx, ttl),
        "Time to live for deduplication records"
    },
    {
        FLB_CONFIG_MAP_SIZE, "cache_size", "100M",
        0, FLB_TRUE, offsetof(struct dedup_ctx, cache_size),
        "Size of the deduplication cache"
    },
    {
        FLB_CONFIG_MAP_SIZE, "write_buffer_size", "64M",
        0, FLB_TRUE, offsetof(struct dedup_ctx, write_buffer_size),
        "Size of the write buffer for deduplication database"
    },
    {
        FLB_CONFIG_MAP_TIME, "compact_interval", "300s",
        0, FLB_TRUE, offsetof(struct dedup_ctx, compact_interval),
        "Interval for automatic database compaction"
    },
    {
        FLB_CONFIG_MAP_STR, "ignore_fields", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct dedup_ctx, ignore_fields),
        "Field names to ignore when calculating record hash"
    },
    {
        FLB_CONFIG_MAP_STR, "ignore_regexes", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct dedup_ctx, ignore_field_patterns),
        "Regex patterns for field names to ignore when calculating record hash"
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_dedup_plugin = {
    .name               = "dedup",
    .description        = "Deduplicate log records",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
