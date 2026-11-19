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

#include <limits.h>
#include <string.h>
#include <fluent-bit/flb_http_retry_after.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_time.h>

#include "s3_store.h"

/* The uploader serializes access to this database with files_mutex. */
static sqlite3_stmt *state_query(struct flb_s3 *ctx, const char *sql,
                                const char *kind, const char *key)
{
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(ctx->uploader_db, sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 1, kind, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return NULL;
    }
    return stmt;
}

void s3_uploader_count_rejected(struct flb_s3 *ctx, int delta)
{
#ifdef FLB_HAVE_METRICS
    if (ctx->uploader_rejected != NULL) {
        cmt_gauge_add(ctx->uploader_rejected, cfl_time_now(), delta, 1,
                      (char *[]) {(char *) flb_output_name(ctx->ins)});
    }
#endif
}

void s3_uploader_storage_status(struct flb_s3 *ctx, int failed)
{
    ctx->uploader_storage_failed = failed;
#ifdef FLB_HAVE_METRICS
    if (ctx->uploader_storage_blocked) {
        cmt_gauge_set(ctx->uploader_storage_blocked, cfl_time_now(), failed, 1,
                      (char *[]) {(char *) flb_output_name(ctx->ins)});
    }
#endif
}

static void report_deadline(struct flb_s3 *ctx, uint64_t deadline)
{
#ifdef FLB_HAVE_METRICS
    if (ctx->uploader_cooldown_deadline) {
        cmt_gauge_set(ctx->uploader_cooldown_deadline, cfl_time_now(), deadline / 1000.0, 1,
                      (char *[]) {(char *) flb_output_name(ctx->ins)});
    }
#endif
}

static int storage_error(struct flb_s3 *ctx)
{
    if (ctx->uploader_storage_failed == FLB_FALSE) {
        flb_plg_error(ctx->ins, "Cannot persist uploader state: %s; suspending uploads",
                      sqlite3_errmsg(ctx->uploader_db));
    }
    s3_uploader_storage_status(ctx, FLB_TRUE);
    return -1;
}

uint64_t s3_uploader_wall_ms(void)
{
    return cfl_time_now() / 1000000;
}

static uint64_t retry_interval_ms(int failures)
{
    if (failures <= 0) {
        return 0;
    }
    return 2000ULL * (failures > 150 ? 150 : failures);
}

int s3_uploader_state_read(struct flb_s3 *ctx, const char *kind, const char *key,
                           struct s3_retry_state *state)
{
    int ret;
    sqlite3_stmt *stmt;
    const unsigned char *uri;
    uint64_t wall;
    uint64_t remaining;
    uint64_t limit;
    int adjusted = FLB_FALSE;

    stmt = state_query(ctx, "SELECT failures, deadline, uri FROM retry "
                            "WHERE kind = ?1 AND id = ?2", kind, key);
    if (stmt == NULL) {
        return storage_error(ctx);
    }
    ret = sqlite3_step(stmt);
    if (ret == SQLITE_ROW) {
        state->failures = sqlite3_column_int(stmt, 0);
        state->until_ms = sqlite3_column_int64(stmt, 1);
        if (strcmp(kind, "chunk") == 0 || strcmp(kind, "complete") == 0) {
            wall = s3_uploader_wall_ms();
            remaining = state->until_ms > wall ? state->until_ms - wall : 0;
            limit = retry_interval_ms(state->failures);
            if (remaining > limit) {
                remaining = limit;
                state->until_ms = wall + remaining;
                adjusted = FLB_TRUE;
            }
            state->retry_at = flb_output_throttle_now_ms() + remaining;
        }
        uri = sqlite3_column_text(stmt, 2);
        if (uri != NULL) {
            state->uri = flb_sds_create((const char *) uri);
            if (state->uri == NULL) {
                ret = SQLITE_NOMEM;
            }
        }
    }
    sqlite3_finalize(stmt);
    if (ret != SQLITE_ROW && ret != SQLITE_DONE) {
        return storage_error(ctx);
    }
    if (adjusted && s3_uploader_state_write(ctx, kind, key, state) < 0) {
        flb_sds_destroy(state->uri);
        state->uri = NULL;
        return -1;
    }
    return 0;
}

struct pending_checkpoint {
    char *sql;
    struct mk_list _head;
};

static int persist_checkpoint(struct flb_s3 *ctx, char *sql)
{
    struct pending_checkpoint *pending;

    if (sql != NULL && mk_list_is_empty(&ctx->pending_checkpoints) == 0 &&
        sqlite3_exec(ctx->uploader_db, sql, NULL, NULL, NULL) == SQLITE_OK) {
        sqlite3_free(sql);
        return 0;
    }
    pending = flb_malloc(sizeof(*pending));
    if (pending == NULL || sql == NULL) {
        flb_free(pending);
        sqlite3_free(sql);
        ctx->checkpoint_lost = FLB_TRUE;
    }
    else {
        pending->sql = sql;
        mk_list_add(&pending->_head, &ctx->pending_checkpoints);
    }
    return storage_error(ctx);
}

int s3_uploader_storage_recover(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct pending_checkpoint *pending;
    struct multipart_upload *upload;

    if (ctx->checkpoint_lost || s3_store_recover_append(ctx) < 0) {
        return -1;
    }
    mk_list_foreach_safe(head, tmp, &ctx->pending_checkpoints) {
        pending = mk_list_entry(head, struct pending_checkpoint, _head);
        if (sqlite3_exec(ctx->uploader_db, pending->sql, NULL, NULL, NULL) != SQLITE_OK) {
            return -1;
        }
        mk_list_del(head);
        sqlite3_free(pending->sql);
        flb_free(pending);
    }
    mk_list_foreach(head, &ctx->uploads) {
        upload = mk_list_entry(head, struct multipart_upload, _head);
        if (upload->upload_state == MULTIPART_UPLOAD_STATE_CHECKPOINT_PENDING &&
            s3_checkpoint_upload(ctx, upload) < 0) {
            return -1;
        }
    }
    s3_uploader_storage_status(ctx, FLB_FALSE);
    flb_plg_info(ctx->ins, "Uploader storage recovered");
    return 0;
}

int s3_uploader_state_write(struct flb_s3 *ctx, const char *kind, const char *key,
                            const struct s3_retry_state *state)
{
    return persist_checkpoint(ctx, sqlite3_mprintf(
        "INSERT OR REPLACE INTO retry VALUES (%Q,%Q,%d,%lld,%Q)",
        kind, key, state->failures, (sqlite3_int64) state->until_ms, state->uri));
}

void s3_uploader_state_delete(struct flb_s3 *ctx, const char *kind, const char *key)
{
    persist_checkpoint(ctx, sqlite3_mprintf("DELETE FROM retry WHERE kind=%Q AND id=%Q",
                                            kind, key));
}

int s3_uploader_save_failure(struct flb_s3 *ctx, const char *kind, const char *key,
                             struct s3_retry_state *state)
{
    uint64_t interval;

    if (state->failures < INT_MAX) {
        state->failures++;
    }
    /* Keep retry intervals bounded for long-lived multipart completions. */
    interval = retry_interval_ms(state->failures);
    state->retry_at = flb_output_throttle_now_ms() + interval;
    state->until_ms = s3_uploader_wall_ms() + interval;
    return s3_uploader_state_write(ctx, kind, key, state);
}

static char *journal_path(struct flb_s3 *ctx, unsigned int generation)
{
    if (generation == 0) {
        return sqlite3_mprintf("%s/uploader.db", ctx->buffer_dir);
    }
    return sqlite3_mprintf("%s/uploader.db.%u", ctx->buffer_dir, generation);
}

/* Keep the corrupt SQLite file and its sidecars together. Opening a successor
 * also leaves the sequence allocator and any independently owned blob DB intact. */
static int open_journal(struct flb_s3 *ctx)
{
    sqlite3_vfs *vfs = sqlite3_vfs_find(NULL);
    sqlite3_stmt *stmt = NULL;
    char *path;
    const unsigned char *result;
    unsigned int generation = 0;
    int exists;
    int ret;

    if (vfs == NULL) {
        return -1;
    }
    while (generation < UINT_MAX) {
        path = journal_path(ctx, generation + 1);
        if (path == NULL) {
            return -1;
        }
        ret = vfs->xAccess(vfs, path, SQLITE_ACCESS_EXISTS, &exists);
        sqlite3_free(path);
        if (ret != SQLITE_OK) {
            return -1;
        }
        if (!exists) {
            break;
        }
        generation++;
    }
    for (;;) {
        path = journal_path(ctx, generation);
        if (path == NULL) {
            return -1;
        }
        ret = sqlite3_open(path, &ctx->uploader_db);
        sqlite3_free(path);
        if (ret == SQLITE_OK) {
            sqlite3_busy_timeout(ctx->uploader_db, 1000);
            ret = sqlite3_prepare_v2(ctx->uploader_db, "PRAGMA quick_check(1)", -1, &stmt, NULL);
        }
        if (ret == SQLITE_OK) {
            ret = sqlite3_step(stmt);
            if (ret == SQLITE_ROW) {
                result = sqlite3_column_text(stmt, 0);
                if (result == NULL) {
                    ret = SQLITE_NOMEM;
                }
                else {
                    ret = strcmp((const char *) result, "ok") == 0 ? SQLITE_OK : SQLITE_CORRUPT;
                }
            }
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (ret == SQLITE_OK) {
            ctx->journal_generation = generation;
            return 0;
        }
        if ((ret != SQLITE_CORRUPT && ret != SQLITE_NOTADB) || generation == UINT_MAX) {
            return storage_error(ctx);
        }
        flb_plg_error(ctx->ins, "Corrupt S3 uploader journal, preserving generation %u "
                      "and replaying buffered files under fresh recovery keys", generation);
        sqlite3_close(ctx->uploader_db);
        ctx->uploader_db = NULL;
        generation++;
    }
}

/* Reconcile against files that survived the last shutdown before admitting any
 * uploads. Seeding new keys and marking recovery complete must commit together. */
int s3_uploader_reconcile_files(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *item;
    struct flb_fstore_stream *stream;
    struct flb_fstore_file *file;
    sqlite3 *db = ctx->uploader_db;
    sqlite3_stmt *stmt = NULL;
    int ret;

    ret = sqlite3_exec(db, "BEGIN IMMEDIATE; CREATE TEMP TABLE spool_ids "
                           "(id TEXT PRIMARY KEY)", NULL, NULL, NULL);
    if (ret == SQLITE_OK) {
        ret = sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO spool_ids VALUES (?)", -1, &stmt, NULL);
    }
    mk_list_foreach(head, &ctx->fs->streams) {
        stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (stream == ctx->stream_upload || stream == ctx->stream_quarantine ||
            strcmp(stream->name, "sequence") == 0) {
            continue;
        }
        mk_list_foreach(item, &stream->files) {
            if (ret != SQLITE_OK) {
                break;
            }
            file = mk_list_entry(item, struct flb_fstore_file, _head);
            ret = sqlite3_bind_text(stmt, 1, file->name, -1, SQLITE_STATIC);
            if (ret == SQLITE_OK) {
                ret = sqlite3_step(stmt);
                if (ret == SQLITE_DONE) {
                    ret = sqlite3_reset(stmt);
                }
            }
        }
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (ret == SQLITE_OK) {
        ret = sqlite3_exec(db, "DELETE FROM retry WHERE kind IN ('chunk','part') "
                               "AND id NOT IN (SELECT id FROM spool_ids)", NULL, NULL, NULL);
    }
    if (ret == SQLITE_OK && ctx->journal_generation > 0) {
        ret = sqlite3_prepare_v2(db, "INSERT INTO retry SELECT 'chunk', id, 0, 0, "
            "'" S3_RECOVERY_PREFIX "' || lower(hex(randomblob(16))) FROM spool_ids "
            "WHERE NOT EXISTS (SELECT 1 FROM retry WHERE kind='recovery' AND id='')",
            -1, &stmt, NULL);
        if (ret == SQLITE_OK) {
            ret = sqlite3_step(stmt);
            if (ret == SQLITE_DONE) {
                ret = sqlite3_exec(db, "INSERT OR IGNORE INTO retry VALUES "
                                       "('recovery','',0,0,NULL)", NULL, NULL, NULL);
            }
        }
        sqlite3_finalize(stmt);
    }
    if (ret == SQLITE_OK) {
        ret = sqlite3_exec(db, "DROP TABLE spool_ids; COMMIT", NULL, NULL, NULL);
    }
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "Cannot reconcile uploader journal: %s", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return 0;
}

int s3_uploader_init(struct flb_s3 *ctx)
{
    int ret;
    uint64_t wall_ms;
    uint64_t remaining;
#ifdef FLB_HAVE_METRICS
    struct cmt_gauge *generation;
#endif
    struct s3_retry_state state = {0};

    if (!ctx->ins->throttle.enabled) {
        return 0;
    }
    ret = flb_output_throttle_init(&ctx->uploader_gate, FLB_TRUE,
                                   ctx->ins->throttle.base_ms, ctx->ins->throttle.cap_ms);
    if (ret != 0) {
        return -1;
    }
    ctx->uploader_gate_initialized = FLB_TRUE;

#ifdef FLB_HAVE_METRICS
    if (ctx->ins->cmt != NULL) {
        ctx->uploader_cooldown_deadline = cmt_gauge_create(ctx->ins->cmt, "fluentbit", "output",
            "s3_uploader_cooldown_until_seconds", "Uploader cooldown deadline in Unix seconds",
            1, (char *[]) {"name"});
        ctx->uploader_spool_full = cmt_gauge_create(ctx->ins->cmt, "fluentbit", "output",
            "s3_uploader_spool_full", "Latest spool admission refused for lack of space",
            1, (char *[]) {"name"});
        ctx->uploader_rejected = cmt_gauge_create(ctx->ins->cmt, "fluentbit", "output",
            "s3_uploader_rejected_uploads", "Rejected multipart uploads awaiting cleanup",
            1, (char *[]) {"name"});
        ctx->uploader_storage_blocked = cmt_gauge_create(ctx->ins->cmt, "fluentbit", "output",
            "s3_uploader_storage_blocked", "Uploader blocked by local storage",
            1, (char *[]) {"name"});
    }
#endif
    if (open_journal(ctx) < 0) {
        return -1;
    }
#ifdef FLB_HAVE_METRICS
    if (ctx->ins->cmt != NULL) {
        generation = cmt_gauge_create(ctx->ins->cmt, "fluentbit", "output",
            "s3_uploader_journal_generation", "Journal replacements following corruption",
            1, (char *[]) {"name"});
        if (generation != NULL) {
            cmt_gauge_set(generation, cfl_time_now(), ctx->journal_generation, 1,
                          (char *[]) {(char *) flb_output_name(ctx->ins)});
        }
    }
#endif
    if (sqlite3_exec(ctx->uploader_db,
                     "PRAGMA synchronous=FULL;"
                     "CREATE TABLE IF NOT EXISTS retry ("
                     "kind TEXT NOT NULL, id TEXT NOT NULL, failures INTEGER NOT NULL,"
                     "deadline INTEGER NOT NULL, uri TEXT, PRIMARY KEY (kind, id));",
                     NULL, NULL, NULL) != SQLITE_OK) {
        return storage_error(ctx);
    }
    if (s3_uploader_state_read(ctx, "gate", "", &state) != 0) {
        return -1;
    }
    flb_sds_destroy(state.uri);
    state.uri = NULL;
    ctx->uploader_gate.consecutive_rounds = state.failures;
    wall_ms = s3_uploader_wall_ms();
    if (state.until_ms > wall_ms) {
        remaining = state.until_ms - wall_ms;
        if (remaining > ctx->uploader_gate.cap_ms) {
            remaining = ctx->uploader_gate.cap_ms;
            state.until_ms = wall_ms + remaining;
            if (s3_uploader_state_write(ctx, "gate", "", &state) < 0) {
                return -1;
            }
        }
        report_deadline(ctx, state.until_ms);
        ctx->uploader_gate.started_ms = flb_output_throttle_now_ms();
        ctx->uploader_gate.until_ms = ctx->uploader_gate.started_ms + remaining;
        ctx->uploader_gate.state = FLB_OUTPUT_THROTTLE_COOLDOWN;
    }
    return 0;
}

void s3_uploader_destroy(struct flb_s3 *ctx)
{
    struct pending_checkpoint *pending;

    if (ctx->uploader_db != NULL) {
        while (mk_list_is_empty(&ctx->pending_checkpoints) != 0) {
            pending = mk_list_entry_first(&ctx->pending_checkpoints, struct pending_checkpoint, _head);
            mk_list_del(&pending->_head);
            sqlite3_free(pending->sql);
            flb_free(pending);
        }
        sqlite3_close(ctx->uploader_db);
    }
    if (ctx->uploader_gate_initialized == FLB_TRUE) {
        flb_output_throttle_destroy(&ctx->uploader_gate);
    }
}

int s3_uploader_admit(struct flb_s3 *ctx, uint64_t *generation)
{
    if (ctx->uploader_gate_initialized == FLB_FALSE) {
        *generation = 0;
        return FLB_TRUE;
    }
    return ctx->ins->config->is_running &&
           (!ctx->uploader_storage_failed || s3_uploader_storage_recover(ctx) == 0) &&
           flb_output_throttle_admit(&ctx->uploader_gate, flb_output_throttle_now_ms(),
                                     generation);
}

int s3_uploader_response(struct flb_s3 *ctx, struct flb_http_client *response,
                         uint64_t generation)
{
    int status;
    int throttled;
    uint64_t random_value = 0;
    uint64_t hint_ms = 0;
    uint64_t now_ms;
    uint64_t wall_ms;
    uint64_t until_ms;
    uint64_t remaining;
    size_t invalid;
    flb_sds_t error = NULL;
    struct s3_retry_state state = {0};
    struct flb_output_throttle_snapshot snapshot;

    if (ctx->uploader_gate_initialized == FLB_FALSE || response == NULL) {
        return FLB_FALSE;
    }
    now_ms = flb_output_throttle_now_ms();
    if (response->resp.payload_size > 0) {
        error = flb_aws_xml_error(response->resp.payload, response->resp.payload_size);
    }
    throttled = response->resp.status == 429 ||
                (response->resp.status == 503 && response->resp.payload_size == 0) ||
                ((response->resp.status == 503 || response->resp.status == 200) &&
                 error != NULL &&
                 (strcmp(error, "SlowDown") == 0 || strcmp(error, "SlowDownWrite") == 0));
    if (throttled) {
        status = FLB_RETRY_AFTER_ABSENT;
        wall_ms = s3_uploader_wall_ms();
        if (response->resp.data != NULL && response->resp.headers_end != NULL) {
            status = flb_http_retry_after_parse_headers(
                response->resp.data, response->resp.headers_end - response->resp.data,
                wall_ms, &hint_ms, &invalid);
        }
        if (hint_ms > ctx->uploader_gate.cap_ms) {
            hint_ms = ctx->uploader_gate.cap_ms;
        }
        flb_random_bytes((unsigned char *) &random_value, sizeof(random_value));
        until_ms = flb_output_throttle_publish(
            &ctx->uploader_gate, now_ms,
            status == FLB_RETRY_AFTER_VALID || status == FLB_RETRY_AFTER_SATURATED,
            hint_ms, random_value);
        flb_output_throttle_snapshot(&ctx->uploader_gate, &snapshot);
        remaining = until_ms - now_ms;
        state.until_ms = remaining > INT64_MAX - wall_ms ? INT64_MAX : wall_ms + remaining;
        state.failures = snapshot.consecutive_rounds > INT_MAX ?
                         INT_MAX : (int) snapshot.consecutive_rounds;
        report_deadline(ctx, state.until_ms);
        s3_uploader_state_write(ctx, "gate", "", &state);
        flb_plg_warn(ctx->ins, "S3 SlowDown, uploader cooling down for %" PRIu64 " ms",
                     remaining);
    }
    else if (error == NULL && response->resp.status >= 200 && response->resp.status < 300) {
        flb_output_throttle_snapshot(&ctx->uploader_gate, &snapshot);
        if (snapshot.consecutive_rounds > 0 && snapshot.generation == generation &&
            now_ms >= snapshot.until_ms) {
            report_deadline(ctx, 0);
            flb_output_throttle_success(&ctx->uploader_gate, now_ms, generation);
            s3_uploader_state_delete(ctx, "gate", "");
        }
    }
    flb_sds_destroy(error);
    return throttled;
}
