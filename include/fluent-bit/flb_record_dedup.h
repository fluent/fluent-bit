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

#ifndef FLB_RECORD_DEDUP_H
#define FLB_RECORD_DEDUP_H

#include <fluent-bit/flb_info.h>
#include <monkey/mk_core.h>
#include <rocksdb/c.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_mp_chunk.h>

#define FLB_RECORD_DEDUP_DEFAULT_TTL 3600  /* 1 hour */
#define FLB_RECORD_DEDUP_DEFAULT_PATH "/tmp/flb-record-dedup"
#define FLB_RECORD_DEDUP_DEFAULT_CACHE_SIZE (100 * 1024 * 1024)  /* 100MB */
#define FLB_RECORD_DEDUP_DEFAULT_WRITE_BUFFER_SIZE (64 * 1024 * 1024)  /* 64MB */
#define FLB_RECORD_DEDUP_DEFAULT_COMPACT_INTERVAL 300  /* 5 minutes */

struct flb_record_dedup_options {
    uint32_t ttl;                /* Time to live in seconds */
    size_t cache_size;          /* Cache size in bytes */
    size_t write_buffer_size;   /* Write buffer size in bytes */
    int compact_interval;       /* Compaction interval in seconds */
    struct mk_list *ignore_fields;        /* List of field names to ignore */
    struct mk_list *ignore_field_patterns; /* List of regex patterns for fields to ignore */
};

struct flb_record_dedup_context {
    rocksdb_t *db;
    rocksdb_options_t *options;
    rocksdb_block_based_table_options_t *table_options;
    rocksdb_cache_t *cache;
    rocksdb_readoptions_t *read_options;
    rocksdb_writeoptions_t *write_options;
    char *path;
    struct flb_record_dedup_options opts;
    /* Internal statistics */
    uint64_t records_added;
    uint64_t records_checked;
    uint64_t hits;
    uint64_t misses;
    /* Ignore fields */
    struct mk_list ignore_fields;         /* List of field names to ignore */
    struct mk_list ignore_field_regexes;  /* List of compiled regex patterns */
    /* Link to global dedup list */
    struct mk_list _head;
};

struct flb_record_dedup_context *flb_record_dedup_context_create(const char *path,
                                                                 struct flb_record_dedup_options *opts);
void flb_record_dedup_destroy(struct flb_record_dedup_context *ctx);

/* Check if record exists (not expired), returns FLB_TRUE if exists, FLB_FALSE if not */
int flb_record_dedup_exists(struct flb_record_dedup_context *ctx,
                            struct flb_mp_chunk_record *record);

/* Add record (uses context TTL) */
int flb_record_dedup_add(struct flb_record_dedup_context *ctx,
                         struct flb_mp_chunk_record *record);


/* Compact database to remove expired entries */
int flb_record_dedup_compact(struct flb_record_dedup_context *ctx);

/* Helper function to get default options */
static inline void flb_record_dedup_options_default(struct flb_record_dedup_options *opts)
{
    opts->ttl = FLB_RECORD_DEDUP_DEFAULT_TTL;
    opts->cache_size = FLB_RECORD_DEDUP_DEFAULT_CACHE_SIZE;
    opts->write_buffer_size = FLB_RECORD_DEDUP_DEFAULT_WRITE_BUFFER_SIZE;
    opts->compact_interval = FLB_RECORD_DEDUP_DEFAULT_COMPACT_INTERVAL;
    opts->ignore_fields = NULL;
    opts->ignore_field_patterns = NULL;
}

#endif