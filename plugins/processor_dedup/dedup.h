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

#ifndef FLB_PROCESSOR_DEDUP_H
#define FLB_PROCESSOR_DEDUP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_record_dedup.h>
#include <fluent-bit/flb_scheduler.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>

struct dedup_ctx {
    /* Configuration */
    flb_sds_t dedup_path;

    /* Deduplication context */
    struct flb_record_dedup_context *dedup;

    /* Config properties */
    int ttl;
    size_t cache_size;
    size_t write_buffer_size;
    int compact_interval;

    /* Ignore fields lists */
    struct mk_list *ignore_fields;
    struct mk_list *ignore_field_patterns;

    /* Processor instance */
    struct flb_processor_instance *ins;

    /* Scheduler for compaction */
    int coll_fd;
    struct flb_sched_timer *timer;
    struct flb_config *config;

    /* CMetrics */
    struct cmt *cmt;
    struct cmt_counter *cmt_records_processed;
    struct cmt_counter *cmt_records_removed;
    struct cmt_counter *cmt_records_kept;
    struct cmt_counter *cmt_compactions;
    struct cmt_gauge *cmt_disk_size_bytes;
    struct cmt_gauge *cmt_live_data_size_bytes;
};

#endif