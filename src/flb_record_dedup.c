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

#include <fluent-bit/flb_record_dedup.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_mp.h>
#include <cfl/cfl_hash.h>
#include <cfl/cfl_object.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <msgpack.h>

/* Structure to hold compiled regex patterns */
struct dedup_regex {
    char *pattern;
    struct flb_regex *regex;
    struct mk_list _head;
};

static int ensure_directory(const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        return -1;
    }

    if (mkdir(path, 0755) != 0) {
        return -1;
    }

    return 0;
}

/* Check if field should be ignored */
static int should_ignore_field(const char *field_name, size_t field_len,
                              struct flb_record_dedup_context *ctx)
{
    struct mk_list *head;
    struct flb_kv *kv;
    struct dedup_regex *regex_entry;

    /* Check exact field matches */
    mk_list_foreach(head, &ctx->ignore_fields) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strlen(kv->key) == field_len &&
            strncmp(kv->key, field_name, field_len) == 0) {
            return FLB_TRUE;
        }
    }

    /* Check regex patterns */
    mk_list_foreach(head, &ctx->ignore_field_regexes) {
        regex_entry = mk_list_entry(head, struct dedup_regex, _head);
        if (flb_regex_match(regex_entry->regex,
                           (unsigned char *)field_name, field_len)) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

/* Hash msgpack data with field filtering using CFL hash */
static uint64_t hash_msgpack_data_filtered(const void *data, size_t size,
                                          struct flb_record_dedup_context *ctx)
{
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object_kv *kv;
    cfl_hash_state_t state;
    cfl_hash_64bits_t hash;
    int i;
    char *key_str;
    size_t key_len;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;

    /* If no filtering needed, hash the raw data */
    if (mk_list_is_empty(&ctx->ignore_fields) &&
        mk_list_is_empty(&ctx->ignore_field_regexes)) {
        return cfl_hash_64bits(data, size);
    }

    /* Parse the msgpack data */
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, data, size, NULL) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        /* Fallback to raw hash if parsing fails */
        return cfl_hash_64bits(data, size);
    }

    /* We expect a map object */
    if (result.data.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&result);
        /* Fallback to raw hash if not a map */
        return cfl_hash_64bits(data, size);
    }

    map = result.data;

    /* Initialize CFL hash state */
    cfl_hash_64bits_reset(&state);

    /* Process each field and update hash state */
    for (i = 0; i < map.via.map.size; i++) {
        kv = &map.via.map.ptr[i];

        /* Get field name */
        if (kv->key.type == MSGPACK_OBJECT_STR) {
            key_str = (char *)kv->key.via.str.ptr;
            key_len = kv->key.via.str.size;
        }
        else if (kv->key.type == MSGPACK_OBJECT_BIN) {
            key_str = (char *)kv->key.via.bin.ptr;
            key_len = kv->key.via.bin.size;
        }
        else {
            /* Non-string key, pack and include it */
            msgpack_sbuffer_init(&sbuf);
            msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
            msgpack_pack_object(&pck, kv->key);
            msgpack_pack_object(&pck, kv->val);
            cfl_hash_64bits_update(&state, sbuf.data, sbuf.size);
            msgpack_sbuffer_destroy(&sbuf);
            continue;
        }

        /* Check if field should be ignored */
        if (!should_ignore_field(key_str, key_len, ctx)) {
            /* Pack key-value pair and update hash */
            msgpack_sbuffer_init(&sbuf);
            msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
            msgpack_pack_object(&pck, kv->key);
            msgpack_pack_object(&pck, kv->val);
            cfl_hash_64bits_update(&state, sbuf.data, sbuf.size);
            msgpack_sbuffer_destroy(&sbuf);
        }
    }

    /* Get final hash */
    hash = cfl_hash_64bits_digest(&state);

    /* Cleanup */
    msgpack_unpacked_destroy(&result);

    return hash;
}


struct flb_record_dedup_context *flb_record_dedup_context_create(const char *path,
                                                                 struct flb_record_dedup_options *opts)
{
    char *err = NULL;
    struct flb_record_dedup_context *ctx;
    rocksdb_filterpolicy_t *filter_policy;
    struct flb_record_dedup_options default_opts;

    ctx = flb_calloc(1, sizeof(struct flb_record_dedup_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Use default options if none provided */
    if (!opts) {
        flb_record_dedup_options_default(&default_opts);
        opts = &default_opts;
    }

    /* Copy options to context */
    ctx->opts = *opts;

    /* Initialize statistics counters */
    ctx->records_added = 0;
    ctx->records_checked = 0;
    ctx->hits = 0;
    ctx->misses = 0;

    ctx->path = flb_strdup(path);
    if (!ctx->path) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    if (ensure_directory(path) != 0) {
        flb_error("[dedup] failed to create directory: %s", path);
        flb_free(ctx->path);
        flb_free(ctx);
        return NULL;
    }

    /* Initialize ignore lists */
    mk_list_init(&ctx->ignore_fields);
    mk_list_init(&ctx->ignore_field_regexes);

    /* Copy ignore fields if provided */
    if (opts->ignore_fields) {
        struct mk_list *head;
        struct flb_kv *src_kv, *new_kv;

        mk_list_foreach(head, opts->ignore_fields) {
            src_kv = mk_list_entry(head, struct flb_kv, _head);
            new_kv = flb_kv_item_create(&ctx->ignore_fields, src_kv->key, src_kv->val);
            if (!new_kv) {
                flb_error("[dedup] failed to copy ignore field: %s", src_kv->key);
            }
        }
    }

    /* Compile regex patterns if provided */
    if (opts->ignore_field_patterns) {
        struct mk_list *head;
        struct flb_kv *src_kv;
        struct dedup_regex *regex_entry;

        mk_list_foreach(head, opts->ignore_field_patterns) {
            src_kv = mk_list_entry(head, struct flb_kv, _head);

            regex_entry = flb_malloc(sizeof(struct dedup_regex));
            if (!regex_entry) {
                flb_error("[dedup] failed to allocate regex entry");
                continue;
            }

            regex_entry->pattern = flb_strdup(src_kv->key);
            regex_entry->regex = flb_regex_create(src_kv->key);

            if (!regex_entry->regex) {
                flb_error("[dedup] failed to compile regex pattern: %s", src_kv->key);
                flb_free(regex_entry->pattern);
                flb_free(regex_entry);
                continue;
            }

            mk_list_add(&regex_entry->_head, &ctx->ignore_field_regexes);
            flb_info("[dedup] compiled ignore regex pattern: %s", src_kv->key);
        }
    }

    /* Create options */
    ctx->options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(ctx->options, 1);

    /* Always enable basic RocksDB statistics for monitoring */
    rocksdb_options_enable_statistics(ctx->options);
    rocksdb_options_set_statistics_level(ctx->options,
        rocksdb_statistics_level_except_detailed_timers);

    /* Create block-based table options */
    ctx->table_options = rocksdb_block_based_options_create();

    /* Set up bloom filter for fast lookups */
    filter_policy = rocksdb_filterpolicy_create_bloom(10);
    rocksdb_block_based_options_set_filter_policy(ctx->table_options, filter_policy);

    /* Use hash index for point lookups */
    rocksdb_block_based_options_set_index_type(ctx->table_options, 1); /* kHashSearch */

    /* Cache index and filter blocks */
    rocksdb_block_based_options_set_cache_index_and_filter_blocks(ctx->table_options, 1);

    /* Create and set block cache */
    ctx->cache = rocksdb_cache_create_lru(ctx->opts.cache_size);
    rocksdb_block_based_options_set_block_cache(ctx->table_options, ctx->cache);

    /* Set table factory */
    rocksdb_options_set_block_based_table_factory(ctx->options, ctx->table_options);

    /* Write buffer settings */
    rocksdb_options_set_write_buffer_size(ctx->options, ctx->opts.write_buffer_size);
    rocksdb_options_set_max_write_buffer_number(ctx->options, 3);
    rocksdb_options_set_target_file_size_base(ctx->options, 64 * 1024 * 1024);

    /* Enable ZSTD compression for better storage efficiency */
    rocksdb_options_set_compression(ctx->options, rocksdb_zstd_compression);

    /* Optimize for point lookups */
    rocksdb_options_optimize_for_point_lookup(ctx->options, ctx->opts.cache_size / (1024 * 1024));

    /* Create read/write options */
    ctx->read_options = rocksdb_readoptions_create();
    ctx->write_options = rocksdb_writeoptions_create();

    /* Open database with TTL support for automatic expiration */
    ctx->db = rocksdb_open_with_ttl(ctx->options, path, ctx->opts.ttl, &err);
    if (err != NULL) {
        flb_error("[dedup] failed to open database: %s", err);
        free(err);

        rocksdb_cache_destroy(ctx->cache);
        rocksdb_options_destroy(ctx->options);
        rocksdb_readoptions_destroy(ctx->read_options);
        rocksdb_writeoptions_destroy(ctx->write_options);
        flb_free(ctx->path);
        flb_free(ctx);
        return NULL;
    }

    flb_info("[dedup] created deduplication database at %s (ttl=%u, cache=%zu, write_buffer=%zu)",
             path, ctx->opts.ttl, ctx->opts.cache_size, ctx->opts.write_buffer_size);

    return ctx;
}

void flb_record_dedup_destroy(struct flb_record_dedup_context *ctx)
{
    char *err = NULL;

    if (!ctx) {
        return;
    }

    if (ctx->db) {
        rocksdb_close(ctx->db);
    }

    /* Remove the database directory and all its contents */
    if (ctx->path && ctx->options) {
        rocksdb_destroy_db(ctx->options, ctx->path, &err);
        if (err != NULL) {
            flb_error("[dedup] failed to destroy database: %s", err);
            free(err);
        }
    }

    if (ctx->cache) {
        rocksdb_cache_destroy(ctx->cache);
    }

    if (ctx->options) {
        rocksdb_options_destroy(ctx->options);
    }

    if (ctx->read_options) {
        rocksdb_readoptions_destroy(ctx->read_options);
    }

    if (ctx->write_options) {
        rocksdb_writeoptions_destroy(ctx->write_options);
    }

    if (ctx->path) {
        flb_free(ctx->path);
    }

    /* Clean up ignore fields */
    flb_kv_release(&ctx->ignore_fields);

    /* Clean up regex patterns */
    struct mk_list *tmp;
    struct mk_list *head;
    struct dedup_regex *regex_entry;

    mk_list_foreach_safe(head, tmp, &ctx->ignore_field_regexes) {
        regex_entry = mk_list_entry(head, struct dedup_regex, _head);
        mk_list_del(&regex_entry->_head);
        if (regex_entry->regex) {
            flb_regex_destroy(regex_entry->regex);
        }
        if (regex_entry->pattern) {
            flb_free(regex_entry->pattern);
        }
        flb_free(regex_entry);
    }

    flb_free(ctx);
}

int flb_record_dedup_exists(struct flb_record_dedup_context *ctx,
                            struct flb_mp_chunk_record *record)
{
    char *err = NULL;
    char *value;
    size_t value_len;
    uint64_t hash;
    char key[8];
    int exists;
    char *mp_buf;
    size_t mp_size;
    int ret;

    if (!ctx || !record || !record->cobj_record) {
        return FLB_FALSE;
    }

    /* Convert CFL object to msgpack for hashing */
    ret = flb_mp_cfl_to_msgpack(record->cobj_record, &mp_buf, &mp_size);
    if (ret != 0) {
        return FLB_FALSE;
    }

    hash = hash_msgpack_data_filtered(mp_buf, mp_size, ctx);
    flb_free(mp_buf);

    memcpy(key, &hash, sizeof(hash));

    /* Increment check counter */
    ctx->records_checked++;

    value = rocksdb_get(ctx->db, ctx->read_options,
                        key, sizeof(key), &value_len, &err);

    if (err != NULL) {
        flb_error("[dedup] error reading from database: %s", err);
        free(err);
        return FLB_FALSE;
    }

    if (value == NULL) {
        exists = FLB_FALSE;
        ctx->misses++;
        flb_trace("[dedup] record not found (hash: %016llx)", (unsigned long long)hash);
    } else {
        /* Check if entry is expired */
        if (value_len == sizeof(time_t)) {
            time_t stored_timestamp;
            memcpy(&stored_timestamp, value, sizeof(stored_timestamp));

            time_t current_time = time(NULL);
            if (current_time - stored_timestamp > ctx->opts.ttl) {
                /* Entry has expired, treat as not found */
                exists = FLB_FALSE;
                ctx->misses++;
                flb_trace("[dedup] record expired (hash: %016llx, age: %ld seconds)",
                         (unsigned long long)hash, (long)(current_time - stored_timestamp));
            } else {
                exists = FLB_TRUE;
                ctx->hits++;
                flb_trace("[dedup] record found (hash: %016llx, age: %ld seconds)",
                         (unsigned long long)hash, (long)(current_time - stored_timestamp));
            }
        } else {
            /* Unexpected value size, treat as valid for backward compatibility */
            exists = FLB_TRUE;
            ctx->hits++;
        }

        free(value);
    }

    return exists;
}

int flb_record_dedup_add(struct flb_record_dedup_context *ctx,
                         struct flb_mp_chunk_record *record)
{
    char *err = NULL;
    uint64_t hash;
    char key[8];
    time_t timestamp;
    char *mp_buf;
    size_t mp_size;
    int ret;

    if (!ctx || !record || !record->cobj_record) {
        return -1;
    }

    /* Convert CFL object to msgpack for hashing */
    ret = flb_mp_cfl_to_msgpack(record->cobj_record, &mp_buf, &mp_size);
    if (ret != 0) {
        return -1;
    }

    hash = hash_msgpack_data_filtered(mp_buf, mp_size, ctx);
    flb_free(mp_buf);

    memcpy(key, &hash, sizeof(hash));

    /* Store current timestamp as the value for TTL checking */
    timestamp = time(NULL);

    rocksdb_put(ctx->db, ctx->write_options,
                key, sizeof(key), (char*)&timestamp, sizeof(timestamp), &err);

    if (err != NULL) {
        flb_error("[dedup] error writing to database: %s", err);
        free(err);
        return -1;
    }

    /* Increment add counter and log */
    ctx->records_added++;
    flb_trace("[dedup] record added (hash: %016llx, ttl: %u)", (unsigned long long)hash, ctx->opts.ttl);

    return 0;
}

int flb_record_dedup_compact(struct flb_record_dedup_context *ctx)
{
    rocksdb_compactoptions_t *compact_opts;

    if (!ctx) {
        return -1;
    }

    /* Create compact options for better control */
    compact_opts = rocksdb_compactoptions_create();

    /*
     * Set bottommost level compaction to force recompaction
     * This ensures expired TTL entries are cleaned up even if
     * files don't overlap. Value 1 typically means kForceOptimized.
     */
    rocksdb_compactoptions_set_bottommost_level_compaction(compact_opts, 1);

    /* Allow exclusive manual compaction to ensure it completes */
    rocksdb_compactoptions_set_exclusive_manual_compaction(compact_opts, 1);

    /*
     * Don't allow write stalls during compaction.
     * This means: "Run the compaction, but if it would cause writes to be blocked,
     * prioritize keeping writes flowing over completing the compaction immediately."
     */
    rocksdb_compactoptions_set_allow_write_stall(compact_opts, 0);

    /* Trigger compaction with options */
    rocksdb_compact_range_opt(ctx->db, compact_opts, NULL, 0, NULL, 0);

    /* Clean up */
    rocksdb_compactoptions_destroy(compact_opts);

    /* Note: rocksdb_compact_range_opt doesn't provide error feedback through errptr
     * It's a fire-and-forget operation that queues the compaction request.
     * Errors would show up in RocksDB logs but not returned to caller.
     */

    flb_info("[dedup] triggered database compaction");

    return 0;
}
