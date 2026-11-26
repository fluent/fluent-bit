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

/*
 * State across restarts
 * =====================
 * With 'state_path' set, what the processor has learned is saved as a
 * snapshot and loaded again on start: the patterns of every group with their
 * counters, their current rate and the counts that are not in a summary yet.
 * Without it a restart forgets everything, so every pattern gets its
 * allowance again and the last window is never accounted for.
 *
 * Storage is one Chunk I/O stream per processor instance:
 *
 *   <state_path>/<scope>.<owner>.<stage>/state/snapshot-<sequence>
 *
 * A snapshot is never modified. A new one is written and synced under the
 * next sequence number, then the previous one is deleted, so a crash at any
 * point leaves at least one complete file. On start the highest sequence
 * that passes its checksum wins.
 *
 * Content: a stream of MessagePack arrays followed by a 16 byte trailer.
 *
 *   header   [version, written, window, depth, max_children, max_tokens,
 *             similarity, groups, [totals], [records by reason]]
 *   group    [key, tag, last_seen, lost_count, lost_kept, lost_dropped,
 *             lost_bytes_dropped, patterns]
 *   pattern  [truncated, key_wildcards, [path], [tokens], exemplar,
 *             counters...]
 *   trailer  8 bytes with the hash of all the above, then STATE_MAGIC
 *
 * Patterns are stored from the least to the most recently seen, which is the
 * order that rebuilds the recency list. The tree is not stored: each pattern
 * carries the keys that lead to its leaf.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_fstore.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_chunk.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "adaptive.h"

#define STATE_VERSION          1
#define STATE_MAGIC            "FLBADPT1"
#define STATE_MAGIC_LEN        8
#define STATE_TRAILER_LEN      16
#define STATE_META             "fluent-bit adaptive processor state"
#define STATE_STREAM           "state"
#define STATE_FILE_PREFIX      "snapshot-"
#define STATE_HEADER_FIELDS    10
#define STATE_GROUP_FIELDS     8
#define STATE_PATTERN_COUNTERS 19
#define STATE_PATTERN_FIELDS   (5 + STATE_PATTERN_COUNTERS + 1)
#define STATE_TOTALS           6
#define STATE_REASONS          (2 * ADAPTIVE_REASON_COUNT)

static void hash_store(unsigned char *out, uint64_t hash)
{
    int i;

    for (i = 0; i < 8; i++) {
        out[i] = (unsigned char) (hash >> (i * 8));
    }
}

static uint64_t hash_load(const unsigned char *in)
{
    int i;
    uint64_t hash = 0;

    for (i = 0; i < 8; i++) {
        hash |= ((uint64_t) in[i]) << (i * 8);
    }

    return hash;
}

static void pack_str(msgpack_packer *pck, const char *str, size_t len)
{
    msgpack_pack_str(pck, len);
    msgpack_pack_str_body(pck, str, len);
}

static void pack_sds(msgpack_packer *pck, cfl_sds_t str)
{
    if (str) {
        pack_str(pck, str, cfl_sds_len(str));
    }
    else {
        msgpack_pack_nil(pck);
    }
}

static int pack_pattern(msgpack_packer *pck, struct adaptive_miner *miner,
                        struct adaptive_pattern *pattern)
{
    int i;
    int count;
    uint64_t path[ADAPTIVE_DEPTH_MAX];

    count = adaptive_miner_pattern_path(miner, pattern, path, ADAPTIVE_DEPTH_MAX);
    if (count < 0) {
        return -1;
    }

    msgpack_pack_array(pck, STATE_PATTERN_FIELDS);

    if (pattern->truncated) {
        msgpack_pack_true(pck);
    }
    else {
        msgpack_pack_false(pck);
    }
    if (pattern->key_wildcards) {
        msgpack_pack_true(pck);
    }
    else {
        msgpack_pack_false(pck);
    }

    msgpack_pack_array(pck, count);
    for (i = 0; i < count; i++) {
        msgpack_pack_uint64(pck, path[i]);
    }

    msgpack_pack_array(pck, pattern->token_count);
    for (i = 0; i < pattern->token_count; i++) {
        pack_str(pck, pattern->tokens[i], strlen(pattern->tokens[i]));
    }

    pack_sds(pck, pattern->exemplar);

    /* STATE_PATTERN_COUNTERS values, read back in the same order */
    msgpack_pack_uint64(pck, pattern->count);
    msgpack_pack_uint64(pck, pattern->bytes);
    msgpack_pack_uint64(pck, pattern->kept);
    msgpack_pack_uint64(pck, pattern->dropped);
    msgpack_pack_uint64(pck, pattern->bytes_dropped);
    msgpack_pack_uint64(pck, pattern->protected_count);
    msgpack_pack_uint64(pck, pattern->first_seen);
    msgpack_pack_uint64(pck, pattern->last_seen);
    msgpack_pack_uint64(pck, pattern->window_id);
    msgpack_pack_uint64(pck, pattern->win_count);
    msgpack_pack_uint64(pck, pattern->win_kept);
    msgpack_pack_uint64(pck, pattern->prev_count);
    msgpack_pack_uint64(pck, pattern->rate);
    msgpack_pack_uint64(pck, pattern->sample_seq);
    msgpack_pack_uint64(pck, pattern->suppressed);
    msgpack_pack_uint64(pck, pattern->sum_count);
    msgpack_pack_uint64(pck, pattern->sum_kept);
    msgpack_pack_uint64(pck, pattern->sum_dropped);
    msgpack_pack_uint64(pck, pattern->sum_bytes_dropped);

    msgpack_pack_double(pck, pattern->policy_acc);

    return 0;
}

static int pack_state(struct adaptive_ctx *ctx, msgpack_packer *pck, uint64_t now)
{
    int action;
    int reason;
    struct cfl_list *head;
    struct cfl_list *p_head;
    struct adaptive_group *group;
    struct adaptive_pattern *pattern;

    msgpack_pack_array(pck, STATE_HEADER_FIELDS);
    msgpack_pack_uint64(pck, STATE_VERSION);
    msgpack_pack_uint64(pck, now);
    msgpack_pack_uint64(pck, ctx->window);
    msgpack_pack_uint64(pck, ctx->depth);
    msgpack_pack_uint64(pck, ctx->max_children);
    msgpack_pack_uint64(pck, ctx->max_tokens);
    msgpack_pack_double(pck, ctx->similarity);
    msgpack_pack_uint64(pck, ctx->group_count);

    msgpack_pack_array(pck, STATE_TOTALS);
    msgpack_pack_uint64(pck, ctx->totals.records);
    msgpack_pack_uint64(pck, ctx->totals.bytes);
    msgpack_pack_uint64(pck, ctx->totals.kept);
    msgpack_pack_uint64(pck, ctx->totals.dropped);
    msgpack_pack_uint64(pck, ctx->totals.bytes_dropped);
    msgpack_pack_uint64(pck, ctx->totals.unmatched);

    msgpack_pack_array(pck, STATE_REASONS);
    for (action = 0; action < 2; action++) {
        for (reason = 0; reason < ADAPTIVE_REASON_COUNT; reason++) {
            msgpack_pack_uint64(pck, ctx->totals.by_reason[action][reason]);
        }
    }

    cfl_list_foreach(head, &ctx->groups) {
        group = cfl_list_entry(head, struct adaptive_group, _head);

        msgpack_pack_array(pck, STATE_GROUP_FIELDS);
        pack_sds(pck, group->key);
        pack_sds(pck, group->tag);
        msgpack_pack_uint64(pck, group->last_seen);
        msgpack_pack_uint64(pck, group->lost_count);
        msgpack_pack_uint64(pck, group->lost_kept);
        msgpack_pack_uint64(pck, group->lost_dropped);
        msgpack_pack_uint64(pck, group->lost_bytes_dropped);
        msgpack_pack_uint64(pck, group->miner->pattern_count);

        /* oldest first: restoring in this order rebuilds the recency list */
        cfl_list_foreach_r(p_head, &group->miner->lru) {
            pattern = cfl_list_entry(p_head, struct adaptive_pattern, _lru);
            if (pack_pattern(pck, group->miner, pattern) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static void state_count(struct adaptive_ctx *ctx, int ok, uint64_t now)
{
    char *labels[6];

    if (ok) {
        ctx->state_writes++;
    }
    else {
        ctx->state_errors++;
    }

    if (ctx->cmt_state) {
        adaptive_labels(ctx, labels);
        labels[5] = ok ? "ok" : "error";
        cmt_counter_add(ctx->cmt_state, now, 1.0, 6, labels);
    }
}

int adaptive_state_write(struct adaptive_ctx *ctx, uint64_t now)
{
    int ret;
    char name[64];
    unsigned char trailer[STATE_TRAILER_LEN];
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    struct flb_fstore_file *file;

    if (!ctx->state_fs) {
        return 0;
    }
    ctx->last_state = now;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    if (pack_state(ctx, &pck, now) != 0) {
        msgpack_sbuffer_destroy(&sbuf);
        state_count(ctx, FLB_FALSE, now);
        return -1;
    }

    hash_store(trailer, cfl_hash_64bits(sbuf.data, sbuf.size));
    memcpy(trailer + 8, STATE_MAGIC, STATE_MAGIC_LEN);
    if (msgpack_sbuffer_write(&sbuf, (const char *) trailer, STATE_TRAILER_LEN) != 0) {
        msgpack_sbuffer_destroy(&sbuf);
        state_count(ctx, FLB_FALSE, now);
        return -1;
    }

    snprintf(name, sizeof(name), STATE_FILE_PREFIX "%020" PRIu64, ctx->state_sequence + 1);

    file = flb_fstore_file_create(ctx->state_fs, ctx->state_stream, name, sbuf.size);
    if (!file) {
        msgpack_sbuffer_destroy(&sbuf);
        state_count(ctx, FLB_FALSE, now);
        return -1;
    }

    /* says what the file is to whoever finds it in the directory */
    ret = flb_fstore_file_meta_set(ctx->state_fs, file, STATE_META, sizeof(STATE_META) - 1);
    if (ret == 0) {
        ret = flb_fstore_file_append(file, sbuf.data, sbuf.size);
    }
    if (ret == 0 && cio_chunk_sync(file->chunk) != CIO_OK) {
        ret = -1;
    }
    ctx->state_bytes = sbuf.size;
    msgpack_sbuffer_destroy(&sbuf);

    if (ret != 0) {
        /* the previous snapshot stays as the one to load */
        flb_fstore_file_delete(ctx->state_fs, file);
        state_count(ctx, FLB_FALSE, now);
        return -1;
    }

    if (ctx->state_file) {
        flb_fstore_file_delete(ctx->state_fs, ctx->state_file);
    }
    ctx->state_file = file;
    ctx->state_sequence++;
    flb_plg_debug(ctx->ins, "state saved as %s: %zu bytes in %" PRIu64 " ms",
                  file->name, (size_t) ctx->state_bytes,
                  (cfl_time_now() - now) / 1000000);
    state_count(ctx, FLB_TRUE, now);

    return 0;
}

static int obj_u64(msgpack_object *obj, uint64_t *out)
{
    if (obj->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return -1;
    }
    *out = obj->via.u64;

    return 0;
}

static int obj_double(msgpack_object *obj, double *out)
{
    if (obj->type == MSGPACK_OBJECT_FLOAT64 || obj->type == MSGPACK_OBJECT_FLOAT32) {
        *out = obj->via.f64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *out = (double) obj->via.u64;
        return 0;
    }

    return -1;
}

static int obj_array(msgpack_object *obj, uint32_t size)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size != size) {
        return -1;
    }

    return 0;
}

/* Returns 0 when the snapshot fits this configuration and is still useful */
static int load_header(struct adaptive_ctx *ctx, msgpack_object *obj, uint64_t now,
                       uint64_t *groups)
{
    int i;
    double similarity;
    uint64_t written;
    uint64_t value[STATE_HEADER_FIELDS];
    uint64_t ttl = (uint64_t) ctx->pattern_ttl * 1000000000ULL;
    msgpack_object *item;
    msgpack_object *list;

    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 1 ||
        obj_u64(&obj->via.array.ptr[0], &value[0]) != 0 || value[0] != STATE_VERSION) {
        flb_plg_warn(ctx->ins, "saved state has another format version, starting empty");
        return -1;
    }

    item = obj->via.array.ptr;
    if (obj_array(obj, STATE_HEADER_FIELDS) != 0 ||
        obj_u64(&item[1], &written) != 0 ||
        obj_u64(&item[2], &value[2]) != 0 || obj_u64(&item[3], &value[3]) != 0 ||
        obj_u64(&item[4], &value[4]) != 0 || obj_u64(&item[5], &value[5]) != 0 ||
        obj_double(&item[6], &similarity) != 0 || obj_u64(&item[7], groups) != 0) {
        flb_plg_warn(ctx->ins, "saved state cannot be read, starting empty");
        return -1;
    }

    /* window ids and tree paths only mean the same under the same settings */
    if (value[2] != (uint64_t) ctx->window || value[3] != (uint64_t) ctx->depth ||
        value[4] != (uint64_t) ctx->max_children ||
        value[5] != (uint64_t) ctx->max_tokens || similarity != ctx->similarity) {
        flb_plg_info(ctx->ins, "window or pattern settings changed since the state "
                     "was saved, starting empty");
        return -1;
    }

    if (ttl > 0 && now > written && now - written > ttl) {
        flb_plg_info(ctx->ins, "saved state is older than pattern_ttl, starting empty");
        return -1;
    }

    list = &item[8];
    if (obj_array(list, STATE_TOTALS) == 0) {
        for (i = 0; i < STATE_TOTALS; i++) {
            if (obj_u64(&list->via.array.ptr[i], &value[i]) != 0) {
                value[i] = 0;
            }
        }
        ctx->totals.records = value[0];
        ctx->totals.bytes = value[1];
        ctx->totals.kept = value[2];
        ctx->totals.dropped = value[3];
        ctx->totals.bytes_dropped = value[4];
        ctx->totals.unmatched = value[5];
    }

    list = &item[9];
    if (obj_array(list, STATE_REASONS) == 0) {
        for (i = 0; i < STATE_REASONS; i++) {
            obj_u64(&list->via.array.ptr[i],
                    &ctx->totals.by_reason[i / ADAPTIVE_REASON_COUNT]
                                          [i % ADAPTIVE_REASON_COUNT]);
        }
    }

    return 0;
}

static struct adaptive_group *load_group(struct adaptive_ctx *ctx, msgpack_object *obj,
                                         uint64_t *patterns)
{
    msgpack_object *item;
    struct adaptive_group *group;

    if (obj_array(obj, STATE_GROUP_FIELDS) != 0) {
        return NULL;
    }
    item = obj->via.array.ptr;

    if (item[0].type != MSGPACK_OBJECT_STR || obj_u64(&item[7], patterns) != 0) {
        return NULL;
    }

    group = adaptive_group_restore(ctx, item[0].via.str.ptr, item[0].via.str.size);
    if (!group) {
        return NULL;
    }

    if (item[1].type == MSGPACK_OBJECT_STR && item[1].via.str.size > 0 && !group->tag) {
        group->tag = cfl_sds_create_len(item[1].via.str.ptr, item[1].via.str.size);
    }

    /* the overflow group can receive several saved groups: add, never set */
    if (item[2].type == MSGPACK_OBJECT_POSITIVE_INTEGER &&
        item[2].via.u64 > group->last_seen) {
        group->last_seen = item[2].via.u64;
    }
    if (item[3].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        group->lost_count += item[3].via.u64;
    }
    if (item[4].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        group->lost_kept += item[4].via.u64;
    }
    if (item[5].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        group->lost_dropped += item[5].via.u64;
    }
    if (item[6].type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        group->lost_bytes_dropped += item[6].via.u64;
    }

    return group;
}

static int load_pattern(struct adaptive_ctx *ctx, struct adaptive_group *group,
                        msgpack_object *obj, const char **tokens, int *lens)
{
    uint32_t i;
    uint64_t path[ADAPTIVE_DEPTH_MAX];
    uint64_t value[STATE_PATTERN_COUNTERS];
    msgpack_object *item;
    msgpack_object *list;
    struct adaptive_pattern *pattern;

    if (obj_array(obj, STATE_PATTERN_FIELDS) != 0) {
        return -1;
    }
    item = obj->via.array.ptr;

    if (item[0].type != MSGPACK_OBJECT_BOOLEAN || item[1].type != MSGPACK_OBJECT_BOOLEAN) {
        return -1;
    }

    list = &item[2];
    if (list->type != MSGPACK_OBJECT_ARRAY || list->via.array.size > ADAPTIVE_DEPTH_MAX) {
        return -1;
    }
    for (i = 0; i < list->via.array.size; i++) {
        if (obj_u64(&list->via.array.ptr[i], &path[i]) != 0) {
            return -1;
        }
    }

    list = &item[3];
    if (list->type != MSGPACK_OBJECT_ARRAY ||
        list->via.array.size > (uint32_t) ctx->max_tokens) {
        return -1;
    }
    for (i = 0; i < list->via.array.size; i++) {
        if (list->via.array.ptr[i].type != MSGPACK_OBJECT_STR) {
            return -1;
        }
        tokens[i] = list->via.array.ptr[i].via.str.ptr;
        lens[i] = (int) list->via.array.ptr[i].via.str.size;
    }

    for (i = 0; i < STATE_PATTERN_COUNTERS; i++) {
        if (obj_u64(&item[5 + i], &value[i]) != 0) {
            return -1;
        }
    }

    pattern = adaptive_miner_restore(group->miner, path, item[2].via.array.size,
                                     tokens, lens, list->via.array.size,
                                     item[0].via.boolean, item[1].via.boolean);
    if (!pattern) {
        return -1;
    }

    if (item[4].type == MSGPACK_OBJECT_STR) {
        pattern->exemplar = cfl_sds_create_len(item[4].via.str.ptr, item[4].via.str.size);
    }

    pattern->count = value[0];
    pattern->bytes = value[1];
    pattern->kept = value[2];
    pattern->dropped = value[3];
    pattern->bytes_dropped = value[4];
    pattern->protected_count = value[5];
    pattern->first_seen = value[6];
    pattern->last_seen = value[7];
    pattern->window_id = value[8];
    pattern->win_count = value[9];
    pattern->win_kept = value[10];
    pattern->prev_count = value[11];
    pattern->rate = (uint32_t) value[12];
    pattern->sample_seq = value[13];
    pattern->suppressed = value[14];
    pattern->sum_count = value[15];
    pattern->sum_kept = value[16];
    pattern->sum_dropped = value[17];
    pattern->sum_bytes_dropped = value[18];
    obj_double(&item[5 + STATE_PATTERN_COUNTERS], &pattern->policy_acc);

    return 0;
}

/* The body is known to be complete here: its hash was checked */
static void load_body(struct adaptive_ctx *ctx, const char *buf, size_t size, uint64_t now)
{
    int skipped = 0;
    int *lens;
    size_t off = 0;
    uint64_t groups;
    uint64_t pending = 0;
    const char **tokens;
    msgpack_unpacked result;
    struct adaptive_group *group = NULL;

    tokens = flb_calloc(ctx->max_tokens, sizeof(char *));
    lens = flb_calloc(ctx->max_tokens, sizeof(int));
    if (!tokens || !lens) {
        flb_errno();
        flb_free(tokens);
        flb_free(lens);
        return;
    }

    msgpack_unpacked_init(&result);

    if (msgpack_unpack_next(&result, buf, size, &off) != MSGPACK_UNPACK_SUCCESS ||
        load_header(ctx, &result.data, now, &groups) != 0) {
        msgpack_unpacked_destroy(&result);
        flb_free(tokens);
        flb_free(lens);
        return;
    }

    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (pending == 0) {
            group = load_group(ctx, &result.data, &pending);
            if (!group) {
                /* without its group the patterns that follow have no place */
                skipped++;
                break;
            }
            ctx->state_restored_groups++;
            continue;
        }

        pending--;
        if (load_pattern(ctx, group, &result.data, tokens, lens) != 0) {
            skipped++;
            continue;
        }
        ctx->state_restored_patterns++;
    }

    msgpack_unpacked_destroy(&result);
    flb_free(tokens);
    flb_free(lens);

    if (skipped > 0) {
        flb_plg_warn(ctx->ins, "%d entries of the saved state could not be restored",
                     skipped);
    }
}

/* Sequence of a snapshot file, or -1 for a file that is not one */
static int file_sequence(struct flb_fstore_file *file, uint64_t *sequence)
{
    char *end;
    size_t prefix = sizeof(STATE_FILE_PREFIX) - 1;

    if (flb_sds_len(file->name) <= prefix ||
        strncmp(file->name, STATE_FILE_PREFIX, prefix) != 0) {
        return -1;
    }

    *sequence = strtoull(file->name + prefix, &end, 10);
    if (*end != '\0') {
        return -1;
    }

    return 0;
}

/* A file is complete when its trailer is in place and the hash agrees */
static int file_read(struct adaptive_ctx *ctx, struct flb_fstore_file *file,
                     char **out_buf, size_t *out_size)
{
    void *buf = NULL;
    size_t size = 0;
    unsigned char *trailer;

    if (flb_fstore_file_content_copy(ctx->state_fs, file, &buf, &size) != 0 || !buf) {
        return -1;
    }

    if (size <= STATE_TRAILER_LEN) {
        flb_free(buf);
        return -1;
    }

    trailer = (unsigned char *) buf + size - STATE_TRAILER_LEN;
    if (memcmp(trailer + 8, STATE_MAGIC, STATE_MAGIC_LEN) != 0 ||
        hash_load(trailer) != cfl_hash_64bits(buf, size - STATE_TRAILER_LEN)) {
        flb_free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_size = size - STATE_TRAILER_LEN;

    return 0;
}

static void state_load(struct adaptive_ctx *ctx, uint64_t now)
{
    int found;
    char *buf = NULL;
    size_t size = 0;
    uint64_t sequence;
    uint64_t best_sequence;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_fstore_file *file;
    struct flb_fstore_file *best;

    /* newest complete snapshot first, whatever fails the check is removed */
    while (!ctx->state_file) {
        best = NULL;
        best_sequence = 0;
        found = FLB_FALSE;

        mk_list_foreach_safe(head, tmp, &ctx->state_stream->files) {
            file = mk_list_entry(head, struct flb_fstore_file, _head);
            if (file_sequence(file, &sequence) != 0) {
                continue;
            }
            found = FLB_TRUE;
            if (!best || sequence > best_sequence) {
                best = file;
                best_sequence = sequence;
            }
        }
        if (!found) {
            return;
        }

        if (best_sequence > ctx->state_sequence) {
            ctx->state_sequence = best_sequence;
        }

        if (file_read(ctx, best, &buf, &size) != 0) {
            flb_plg_warn(ctx->ins, "state file %s is incomplete or damaged, ignoring it",
                         best->name);
            flb_fstore_file_delete(ctx->state_fs, best);
            continue;
        }
        ctx->state_file = best;
    }

    /* older snapshots are only left behind by a crash between two steps */
    mk_list_foreach_safe(head, tmp, &ctx->state_stream->files) {
        file = mk_list_entry(head, struct flb_fstore_file, _head);
        if (file != ctx->state_file && file_sequence(file, &sequence) == 0) {
            flb_fstore_file_delete(ctx->state_fs, file);
        }
    }

    load_body(ctx, buf, size, now);
    flb_free(buf);

    if (ctx->state_restored_patterns > 0 || ctx->state_restored_groups > 0) {
        flb_plg_info(ctx->ins, "state restored from %s: %d groups, %d patterns",
                     ctx->state_file->name, ctx->state_restored_groups,
                     ctx->state_restored_patterns);
    }
}

/* Directory name of this instance: only characters that are safe in a path */
static flb_sds_t state_root(struct adaptive_ctx *ctx)
{
    size_t i;
    size_t start;
    flb_sds_t path;

    path = flb_sds_create_size(256);
    if (!path) {
        return NULL;
    }

    if (!flb_sds_printf(&path, "%s/", ctx->state_path)) {
        flb_sds_destroy(path);
        return NULL;
    }
    start = flb_sds_len(path);

    if (!flb_sds_printf(&path, "%s.%s.%s", ctx->label_scope, ctx->label_owner,
                        ctx->label_stage)) {
        flb_sds_destroy(path);
        return NULL;
    }

    for (i = start; i < flb_sds_len(path); i++) {
        if ((path[i] >= 'a' && path[i] <= 'z') || (path[i] >= 'A' && path[i] <= 'Z') ||
            (path[i] >= '0' && path[i] <= '9') || path[i] == '.' || path[i] == '-' ||
            path[i] == '_') {
            continue;
        }
        path[i] = '_';
    }

    return path;
}

int adaptive_state_open(struct adaptive_ctx *ctx, uint64_t now)
{
    flb_sds_t root;

    if (!ctx->state_path) {
        return 0;
    }
    ctx->last_state = now;

    root = state_root(ctx);
    if (!root) {
        return -1;
    }

    ctx->state_fs = flb_fstore_create(root, FLB_FSTORE_FS);
    if (!ctx->state_fs) {
        flb_plg_error(ctx->ins, "could not use %s to keep state", root);
        flb_sds_destroy(root);
        return -1;
    }
    flb_sds_destroy(root);

    ctx->state_stream = flb_fstore_stream_create(ctx->state_fs, STATE_STREAM);
    if (!ctx->state_stream) {
        adaptive_state_close(ctx);
        return -1;
    }

    state_load(ctx, now);

    return 0;
}

void adaptive_state_close(struct adaptive_ctx *ctx)
{
    if (ctx->state_fs) {
        flb_fstore_destroy(ctx->state_fs);
    }
    ctx->state_fs = NULL;
    ctx->state_stream = NULL;
    ctx->state_file = NULL;
}
