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

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_task.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_batch.h"
#include "azure_logs_ingestion_conf.h"

#define AZLI_SCHEMA_VERSION      3
#define AZLI_TIMER_MS            1000
#define AZLI_SOURCE_DB_RESERVE   4096
#define AZLI_REQUEST_DB_RESERVE  4096
#define AZLI_MEMBER_DB_RESERVE   128
#define AZLI_RECEIPT_DB_RESERVE  256
#define AZLI_MAINTENANCE_SECONDS 60
#define AZLI_WAL_AUTOCHECKPOINT  64
#define AZLI_WAL_LIMIT_MAX       (4 * 1024 * 1024)
#define AZLI_MAX_REQUEST_SOURCES 8
#define AZLI_MAX_COMPRESSION_PROBES 8
#define AZLI_MAX_UPLOADS_PER_TICK 4
#define AZLI_MAX_SOURCE_FILES    10000
#define AZLI_SOURCE_EXISTS_NONE       0
#define AZLI_SOURCE_EXISTS_MATCH      1
#define AZLI_SOURCE_EXISTS_ERROR     -1
#define AZLI_SOURCE_EXISTS_COLLISION -2
#define AZLI_SOURCE_READY        1
#define AZLI_SOURCE_DRAINED      2
#define AZLI_SOURCE_QUARANTINED  3
#define AZLI_REQUEST_READY       1
#define AZLI_REQUEST_INFLIGHT    2
#define AZLI_REQUEST_RETRY       3
#define AZLI_REQUEST_ACKED       4
#define AZLI_REQUEST_QUARANTINED 5
#define AZLI_DIGEST_SIZE         32
#define AZLI_HEX_SIZE            (AZLI_DIGEST_SIZE * 2)

struct azli_instance_lease {
    flb_sds_t instance_key;
    struct mk_list _head;
};

struct azli_root_manager {
    flb_sds_t path;
    size_t limit;
    size_t used;
    size_t logical_used;
    size_t physical_used;
    size_t database_bytes;
    size_t wal_bytes;
    size_t shm_bytes;
    size_t files;
    size_t reserved_bytes;
    int64_t last_maintenance;
    size_t page_size;
    size_t max_page_count;
    size_t wal_headroom;
    int references;
    int lock_fd;
    struct mk_list instance_leases;
    struct flb_sqldb *db;
    pthread_mutex_t mutex;
    struct mk_list _head;
};

struct azli_candidate_source {
    int64_t source_pk;
    int64_t created;
    int64_t record_count;
    int64_t json_bytes;
    int64_t standalone_gzip_bytes;
    void *content;
    size_t content_size;
};

struct azli_request {
    int64_t request_pk;
    int state;
    int attempts;
    int64_t next_retry;
    int64_t json_bytes;
    int64_t gzip_bytes;
    flb_sds_t name;
    unsigned char json_digest[AZLI_DIGEST_SIZE];
    void *body;
    size_t body_size;
    unsigned char digest[AZLI_DIGEST_SIZE];
};

struct flb_az_li_batch {
    struct azli_root_manager *manager;
    pthread_mutex_t lifecycle_mutex;
    int lifecycle_initialized;
    int lock_fd;
    int upload_in_progress;
    int uploader_started;
    struct flb_sched_timer *uploader_retry_timer;
    int shutting_down;
    int fatal_error;
    int persistence_degraded;
    int consecutive_failures;
    int64_t next_recovery;
    uint64_t request_sequence;
    struct azli_instance_lease *lease;
};

static int request_commit_sources(struct flb_az_li *ctx,
                                  struct azli_request *request,
                                  int quarantine, int status,
                                  const char *reason);

static pthread_mutex_t manager_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t manager_registry_once = PTHREAD_ONCE_INIT;
static struct mk_list manager_registry;

static void manager_registry_init(void)
{
    mk_list_init(&manager_registry);
}

static int64_t now_seconds(void)
{
    return (int64_t) time(NULL);
}

#ifdef FLB_HAVE_METRICS
static void metric_counter_add(struct flb_az_li *ctx, struct cmt_counter *counter,
                               double value)
{
    char *output_name;

    if (counter == NULL || ctx->payload_metrics_mutex_initialized != FLB_TRUE) {
        return;
    }
    output_name = (char *) flb_output_name(ctx->ins);
    pthread_mutex_lock(&ctx->payload_metrics_mutex);
    cmt_counter_add(counter, cfl_time_now(), value, 2,
                    (char *[]) {output_name, ctx->dcr_id});
    pthread_mutex_unlock(&ctx->payload_metrics_mutex);
}

static void metric_gauge_set(struct flb_az_li *ctx, struct cmt_gauge *gauge,
                             double value)
{
    char *output_name;

    if (gauge == NULL || ctx->payload_metrics_mutex_initialized != FLB_TRUE) {
        return;
    }
    output_name = (char *) flb_output_name(ctx->ins);
    pthread_mutex_lock(&ctx->payload_metrics_mutex);
    cmt_gauge_set(gauge, cfl_time_now(), value, 2,
                  (char *[]) {output_name, ctx->dcr_id});
    pthread_mutex_unlock(&ctx->payload_metrics_mutex);
}
#else
#define metric_counter_add(ctx, counter, value) do { } while (0)
#define metric_gauge_set(ctx, gauge, value) do { } while (0)
#endif

static int sync_directory(const char *path)
{
#ifdef _WIN32
    (void) path;
    return 0;
#else
    int descriptor;
    int result;

    descriptor = open(path, O_RDONLY);
    if (descriptor == -1) {
        return -1;
    }
    result = fsync(descriptor);
    close(descriptor);
    return result;
#endif
}

static int lock_manager_root(struct azli_root_manager *manager)
{
#ifndef _WIN32
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/.azure_logs_ingestion.owner.lock",
             manager->path);
    manager->lock_fd = open(path, O_CREAT | O_RDWR, 0600);
    if (manager->lock_fd == -1 ||
        flock(manager->lock_fd, LOCK_EX | LOCK_NB) == -1) {
        if (manager->lock_fd != -1) {
            close(manager->lock_fd);
            manager->lock_fd = -1;
        }
        return -1;
    }
    return sync_directory(manager->path);
#else
    (void) manager;
    return -1;
#endif
}

static void unlock_manager_root(struct azli_root_manager *manager)
{
#ifndef _WIN32
    if (manager->lock_fd != -1) {
        flock(manager->lock_fd, LOCK_UN);
        close(manager->lock_fd);
        manager->lock_fd = -1;
    }
#else
    (void) manager;
#endif
}

static int sql_exec(struct azli_root_manager *manager, const char *sql)
{
    char *error;
    int ret;

    error = NULL;
    ret = sqlite3_exec(manager->db->handler, sql, NULL, NULL, &error);
    if (ret != SQLITE_OK) {
        if (error != NULL) {
            flb_error("[azure_logs_ingestion] sqlite: %s", error);
            sqlite3_free(error);
        }
        return -1;
    }
    return 0;
}

static int sql_rollback_if_active(struct azli_root_manager *manager)
{
    if (sqlite3_get_autocommit(manager->db->handler) != 0) {
        return 0;
    }
    return sql_exec(manager, "ROLLBACK");
}

static int sql_commit(struct azli_root_manager *manager)
{
    if (sql_exec(manager, "COMMIT") == 0) {
        return 0;
    }

    /*
     * A failed COMMIT can still have completed. Only an autocommit connection
     * may be queried to reconcile that outcome. Otherwise, make the rollback
     * result explicit so callers never mistake an unresolved transaction for
     * durable state.
     */
    if (sqlite3_get_autocommit(manager->db->handler) != 0) {
        return 1;
    }
    if (sql_rollback_if_active(manager) == 0) {
        return -1;
    }
    return -2;
}

static int hash_bytes(const void *data, size_t size,
                      unsigned char digest[AZLI_DIGEST_SIZE])
{
    return flb_hash_simple(FLB_HASH_SHA256, (unsigned char *) data, size,
                           digest, AZLI_DIGEST_SIZE);
}

static void digest_hex(const unsigned char digest[AZLI_DIGEST_SIZE],
                       char output[AZLI_HEX_SIZE + 1])
{
    static const char digits[] = "0123456789abcdef";
    int index;

    for (index = 0; index < AZLI_DIGEST_SIZE; index++) {
        output[index * 2] = digits[digest[index] >> 4];
        output[index * 2 + 1] = digits[digest[index] & 0x0f];
    }
    output[AZLI_HEX_SIZE] = '\0';
}

static size_t file_size(const char *path)
{
    struct stat file_info;

    if (stat(path, &file_info) == -1 || file_info.st_size < 0) {
        return 0;
    }
    return (size_t) file_info.st_size;
}

static int manager_recount(struct azli_root_manager *manager)
{
    sqlite3_stmt *statement;
    char path[PATH_MAX];
    int ret;

    statement = NULL;
    ret = sqlite3_prepare_v2(manager->db->handler,
            "SELECT COALESCE((SELECT SUM(bytes) FROM azli_sources),0) + "
            "COALESCE((SELECT SUM(bytes) FROM azli_requests),0) + "
            "COALESCE((SELECT SUM(bytes) FROM azli_receipts),0), "
            "(SELECT COUNT(*) FROM azli_sources) + "
            "(SELECT COUNT(*) FROM azli_requests)", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    manager->logical_used = (size_t) sqlite3_column_int64(statement, 0);
    manager->files = (size_t) sqlite3_column_int64(statement, 1);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return -1;
    }

    manager->database_bytes = file_size(manager->db->path);
    snprintf(path, sizeof(path), "%s-wal", manager->db->path);
    manager->wal_bytes = file_size(path);
    snprintf(path, sizeof(path), "%s-shm", manager->db->path);
    manager->shm_bytes = file_size(path);
    manager->physical_used = manager->database_bytes + manager->wal_bytes +
                             manager->shm_bytes;
    manager->used = manager->logical_used;
    return 0;
}

static int manager_checkpoint(struct azli_root_manager *manager, int mode)
{
    int log_frames;
    int checkpointed_frames;
    int ret;

    log_frames = 0;
    checkpointed_frames = 0;
    ret = sqlite3_wal_checkpoint_v2(manager->db->handler, NULL, mode,
                                    &log_frames, &checkpointed_frames);
    if (ret == SQLITE_BUSY) {
        return 1;
    }
    return ret == SQLITE_OK ? 0 : -1;
}

static int manager_maintain(struct azli_root_manager *manager, int truncate)
{
    int ret;

    if (sqlite3_get_autocommit(manager->db->handler) == 0) {
        return 1;
    }
    ret = manager_checkpoint(manager, truncate ? SQLITE_CHECKPOINT_TRUNCATE :
                                                 SQLITE_CHECKPOINT_PASSIVE);
    if (ret < 0) {
        return -1;
    }
    if (manager_recount(manager) == -1) {
        return -1;
    }
    manager->last_maintenance = now_seconds();
    return ret;
}

static int manager_has_physical_capacity(struct azli_root_manager *manager,
                                         size_t transaction_bytes)
{
    size_t pages;
    size_t reserve;

    if (manager->page_size == 0 ||
        transaction_bytes > SIZE_MAX - manager->reserved_bytes) {
        return -1;
    }
    transaction_bytes += manager->reserved_bytes;
    pages = transaction_bytes / manager->page_size + 2;
    if (pages > SIZE_MAX / manager->page_size / 2) {
        return 0;
    }
    reserve = pages * manager->page_size * 2;
    if (manager->physical_used > manager->limit ||
        reserve > manager->limit - manager->physical_used) {
        return 0;
    }
    return 1;
}

static void metrics_refresh_locked(struct flb_az_li *ctx)
{
#ifdef FLB_HAVE_METRICS
    sqlite3_stmt *statement;
    int64_t oldest;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT COUNT(*),COALESCE(SUM(record_count),0),"
            "COALESCE(SUM(json_bytes),0),COALESCE(MIN(created),0) "
            "FROM azli_sources WHERE instance_key=? AND state=1", -1,
            &statement, NULL);
    if (ret == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW) {
            metric_gauge_set(ctx, ctx->cmt_queued_chunks,
                             sqlite3_column_double(statement, 0));
            metric_gauge_set(ctx, ctx->cmt_queued_records,
                             sqlite3_column_double(statement, 1));
            metric_gauge_set(ctx, ctx->cmt_queued_bytes,
                             sqlite3_column_double(statement, 2));
            oldest = sqlite3_column_int64(statement, 3);
            metric_gauge_set(ctx, ctx->cmt_oldest_queued_age,
                             oldest > 0 ? (double) (now_seconds() - oldest) : 0.0);
        }
        sqlite3_finalize(statement);
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT COUNT(*),COALESCE(SUM(json_bytes),0) FROM azli_sources "
            "WHERE instance_key=? AND state=3", -1, &statement, NULL);
    if (ret == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW) {
            metric_gauge_set(ctx, ctx->cmt_quarantined_chunks_current,
                             sqlite3_column_double(statement, 0));
            metric_gauge_set(ctx, ctx->cmt_quarantined_bytes,
                             sqlite3_column_double(statement, 1));
        }
        sqlite3_finalize(statement);
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT last_success FROM azli_instances WHERE instance_key=?", -1,
            &statement, NULL);
    if (ret == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) == SQLITE_ROW) {
            metric_gauge_set(ctx, ctx->cmt_uploader_last_success,
                             sqlite3_column_double(statement, 0));
        }
        sqlite3_finalize(statement);
    }
    metric_gauge_set(ctx, ctx->cmt_quota_used_bytes,
                     (double) ctx->batch->manager->logical_used);
    metric_gauge_set(ctx, ctx->cmt_quota_limit_bytes,
                     (double) ctx->batch->manager->limit);
    metric_gauge_set(ctx, ctx->cmt_uploader_up,
                     ctx->batch->fatal_error ? 0.0 : 1.0);
    metric_gauge_set(ctx, ctx->cmt_uploader_consecutive_failures,
                     (double) ctx->batch->consecutive_failures);
#else
    (void) ctx;
#endif
}

static int database_has_legacy_schema(struct azli_root_manager *manager)
{
    sqlite3_stmt *statement;
    int count;
    int ret;

    statement = NULL;
    ret = sqlite3_prepare_v2(manager->db->handler,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'azli_%'", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    count = sqlite3_column_int(statement, 0);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return -1;
    }
    return count > 0;
}

static int manager_schema(struct azli_root_manager *manager)
{
    sqlite3_stmt *statement;
    int legacy;
    int version;
    int ret;
    const char *schema;

    statement = NULL;
    ret = sqlite3_prepare_v2(manager->db->handler, "PRAGMA user_version", -1,
                             &statement, NULL);
    if (ret != SQLITE_OK || sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    version = sqlite3_column_int(statement, 0);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        return -1;
    }

    if (version == 0) {
        legacy = database_has_legacy_schema(manager);
        if (legacy != 0) {
            if (legacy > 0) {
                flb_error("[azure_logs_ingestion] incompatible record-range spool schema; "
                          "drain, archive, or reset it with the prototype build");
            }
            return -1;
        }
    }
    else if (version != AZLI_SCHEMA_VERSION) {
        flb_error("[azure_logs_ingestion] unsupported spool schema version=%d expected=%d",
                  version, AZLI_SCHEMA_VERSION);
        return -1;
    }

    if (sql_exec(manager, "PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;"
                          "PRAGMA foreign_keys=ON;PRAGMA wal_autocheckpoint=64;") == -1) {
        return -1;
    }
    if (version == AZLI_SCHEMA_VERSION) {
        return 0;
    }

    schema =
        "BEGIN IMMEDIATE;"
        "CREATE TABLE azli_settings("
        " root TEXT PRIMARY KEY, disk_limit INTEGER NOT NULL CHECK(disk_limit>0));"
        "CREATE TABLE azli_instances("
        " instance_key TEXT PRIMARY KEY,"
        " destination BLOB NOT NULL CHECK(length(destination)=32),"
        " last_success INTEGER NOT NULL DEFAULT 0 CHECK(last_success>=0));"
        "CREATE TABLE azli_requests("
        " request_pk INTEGER PRIMARY KEY AUTOINCREMENT,"
        " instance_key TEXT NOT NULL REFERENCES azli_instances(instance_key),"
        " name TEXT NOT NULL UNIQUE,"
        " state INTEGER NOT NULL CHECK(state IN (1,2,3,4,5)),"
        " attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),"
        " next_retry INTEGER NOT NULL DEFAULT 0 CHECK(next_retry>=0),"
        " json_bytes INTEGER NOT NULL CHECK(json_bytes>=2),"
        " gzip_bytes INTEGER NOT NULL CHECK(gzip_bytes>0 AND gzip_bytes<=1048576),"
        " body BLOB NOT NULL CHECK(length(body)=gzip_bytes),"
        " body_digest BLOB NOT NULL CHECK(length(body_digest)=32),"
        " json_digest BLOB NOT NULL CHECK(length(json_digest)=32),"
        " bytes INTEGER NOT NULL CHECK(bytes>=gzip_bytes),"
        " created INTEGER NOT NULL CHECK(created>0),"
        " status INTEGER NOT NULL DEFAULT 0 CHECK(status>=0), reason TEXT,"
        " UNIQUE(instance_key,request_pk));"
        "CREATE INDEX azli_requests_order "
        " ON azli_requests(instance_key,request_pk);"
        "CREATE UNIQUE INDEX azli_one_active_request "
        " ON azli_requests(instance_key) WHERE state IN (1,2,3,4);"
        "CREATE TABLE azli_sources("
        " source_pk INTEGER PRIMARY KEY AUTOINCREMENT,"
        " instance_key TEXT NOT NULL REFERENCES azli_instances(instance_key),"
        " source_id TEXT NOT NULL CHECK(length(source_id)=64),"
        " name TEXT NOT NULL CHECK(length(name)>0),"
        " digest BLOB NOT NULL CHECK(length(digest)=32),"
        " content BLOB NOT NULL CHECK(length(content)=json_bytes),"
        " record_count INTEGER NOT NULL CHECK(record_count>0),"
        " json_bytes INTEGER NOT NULL CHECK(json_bytes>=2),"
        " standalone_gzip_bytes INTEGER NOT NULL "
        " CHECK(standalone_gzip_bytes>0 AND standalone_gzip_bytes<=1048576),"
        " bytes INTEGER NOT NULL CHECK(bytes>=json_bytes),"
        " created INTEGER NOT NULL CHECK(created>0),"
        " state INTEGER NOT NULL CHECK(state IN (1,2,3)),"
        " request_pk INTEGER, quarantine_reason TEXT,"
        " UNIQUE(instance_key,source_id),"
        " FOREIGN KEY(instance_key,request_pk)"
        " REFERENCES azli_requests(instance_key,request_pk));"
        "CREATE INDEX azli_sources_order "
        " ON azli_sources(instance_key,state,source_pk);"
        "CREATE INDEX azli_sources_request ON azli_sources(request_pk,source_pk);"
        "CREATE TABLE azli_receipts("
        " instance_key TEXT NOT NULL REFERENCES azli_instances(instance_key),"
        " source_id TEXT NOT NULL CHECK(length(source_id)=64),"
        " digest BLOB NOT NULL CHECK(length(digest)=32),"
        " completed INTEGER NOT NULL CHECK(completed>0),"
        " expires INTEGER NOT NULL CHECK(expires>completed),"
        " bytes INTEGER NOT NULL CHECK(bytes>=256),"
        " PRIMARY KEY(instance_key,source_id));"
        "PRAGMA user_version=3;"
        "COMMIT;";

    if (sql_exec(manager, schema) == -1) {
        sql_rollback_if_active(manager);
        return -1;
    }
    return 0;
}

static int manager_validate_invariants(struct azli_root_manager *manager)
{
    sqlite3_stmt *statement;
    int invalid;
    int ret;
    const char *query;

    query =
        "SELECT "
        "(SELECT COUNT(*) FROM azli_instances i WHERE "
        " length(i.destination)!=32 OR i.last_success<0) + "
        "(SELECT COUNT(*) FROM azli_requests r WHERE "
        " r.state NOT IN (1,2,3,4,5) OR r.attempts<0 OR r.next_retry<0 OR "
        " r.json_bytes<2 OR r.gzip_bytes<1 OR r.gzip_bytes>1048576 OR "
        " length(r.body)!=r.gzip_bytes OR length(r.body_digest)!=32 OR "
        " length(r.json_digest)!=32 OR "
        " r.bytes<r.gzip_bytes OR r.created<=0 OR r.status<0 OR "
        " NOT EXISTS(SELECT 1 FROM azli_instances i "
        " WHERE i.instance_key=r.instance_key) OR "
        " NOT EXISTS(SELECT 1 FROM azli_sources s "
        " WHERE s.request_pk=r.request_pk AND s.instance_key=r.instance_key)) + "
        "(SELECT COUNT(*) FROM azli_sources s WHERE "
        " s.state NOT IN (1,2,3) OR length(s.source_id)!=64 OR "
        " length(s.name)=0 OR length(s.digest)!=32 OR "
        " length(s.content)!=s.json_bytes OR s.record_count<=0 OR "
        " s.json_bytes<2 OR s.standalone_gzip_bytes<1 OR "
        " s.standalone_gzip_bytes>1048576 OR s.bytes<s.json_bytes OR "
        " s.created<=0 OR "
        " NOT EXISTS(SELECT 1 FROM azli_instances i "
        " WHERE i.instance_key=s.instance_key) OR "
        " (s.request_pk IS NOT NULL AND NOT EXISTS("
        " SELECT 1 FROM azli_requests r WHERE r.request_pk=s.request_pk "
        " AND r.instance_key=s.instance_key)) OR "
        " (s.request_pk IS NULL AND s.state=2) OR "
        " (s.request_pk IS NOT NULL AND NOT EXISTS("
        " SELECT 1 FROM azli_requests r WHERE r.request_pk=s.request_pk AND "
        " ((s.state=1 AND r.state IN (1,2,3)) OR "
        " (s.state=2 AND r.state=4) OR (s.state=3 AND r.state=5))))) + "
        "(SELECT COUNT(*) FROM azli_receipts p WHERE "
        " length(p.source_id)!=64 OR length(p.digest)!=32 OR p.completed<=0 OR "
        " p.expires<=p.completed OR p.bytes<256 OR "
        " NOT EXISTS(SELECT 1 FROM azli_instances i "
        " WHERE i.instance_key=p.instance_key) OR EXISTS("
        " SELECT 1 FROM azli_sources s WHERE s.instance_key=p.instance_key "
        " AND s.source_id=p.source_id AND (s.state!=2 OR s.digest!=p.digest)))";

    ret = sqlite3_prepare_v2(manager->db->handler, query, -1, &statement, NULL);
    if (ret != SQLITE_OK || sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    invalid = sqlite3_column_int(statement, 0);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE || invalid != 0) {
        if (invalid != 0) {
            flb_error("[azure_logs_ingestion] spool invariant violation rows=%d",
                      invalid);
        }
        return -1;
    }
    return 0;
}

static int manager_configure_limits(struct azli_root_manager *manager)
{
    sqlite3_stmt *statement;
    char sql[160];
    size_t main_limit;
    int64_t effective_pages;
    int ret;

    statement = NULL;
    ret = sqlite3_prepare_v2(manager->db->handler, "PRAGMA page_size", -1,
                             &statement, NULL);
    if (ret != SQLITE_OK || sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    manager->page_size = (size_t) sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    if (manager->page_size == 0) {
        return -1;
    }
    manager->wal_headroom = manager->limit / 4;
    if (manager->wal_headroom > AZLI_WAL_LIMIT_MAX) {
        manager->wal_headroom = AZLI_WAL_LIMIT_MAX;
    }
    if (manager->wal_headroom < manager->page_size * 16) {
        manager->wal_headroom = manager->page_size * 16;
    }
    main_limit = manager->limit > manager->wal_headroom + manager->page_size * 16 ?
                 manager->limit - manager->wal_headroom - manager->page_size * 16 :
                 manager->page_size * 32;
    manager->max_page_count = main_limit / manager->page_size;
    snprintf(sql, sizeof(sql), "PRAGMA journal_size_limit=%zu;",
             manager->wal_headroom);
    if (sql_exec(manager, sql) == -1) {
        return -1;
    }
    snprintf(sql, sizeof(sql), "PRAGMA max_page_count=%zu",
             manager->max_page_count);
    ret = sqlite3_prepare_v2(manager->db->handler, sql, -1, &statement, NULL);
    if (ret != SQLITE_OK || sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    effective_pages = sqlite3_column_int64(statement, 0);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE || effective_pages <= 0 ||
        (uint64_t) effective_pages != manager->max_page_count) {
        flb_error("[azure_logs_ingestion] cannot enforce SQLite max_page_count "
                  "requested=%zu effective=%" PRId64,
                  manager->max_page_count, effective_pages);
        return -1;
    }
    return 0;
}

static struct azli_root_manager *manager_acquire(struct flb_az_li *ctx)
{
    char db_path[PATH_MAX];
    char canonical_path[PATH_MAX];
    const char *root_path;
    struct mk_list *head;
    struct azli_root_manager *manager;
    sqlite3_stmt *statement;
    int ret;
    int64_t stored_limit;

    statement = NULL;
    pthread_once(&manager_registry_once, manager_registry_init);
#ifdef _WIN32
    root_path = ctx->buffer_dir;
#else
    root_path = realpath(ctx->buffer_dir, canonical_path);
    if (root_path == NULL) {
        root_path = ctx->buffer_dir;
    }
#endif
    pthread_mutex_lock(&manager_registry_mutex);
    mk_list_foreach(head, &manager_registry) {
        manager = mk_list_entry(head, struct azli_root_manager, _head);
        if (strcmp(manager->path, root_path) == 0) {
            if (manager->limit != ctx->buffer_dir_limit_size) {
                pthread_mutex_unlock(&manager_registry_mutex);
                flb_plg_error(ctx->ins, "buffer root has conflicting aggregate limits");
                return NULL;
            }
            manager->references++;
            pthread_mutex_unlock(&manager_registry_mutex);
            return manager;
        }
    }

    manager = flb_calloc(1, sizeof(*manager));
    if (manager == NULL) {
        pthread_mutex_unlock(&manager_registry_mutex);
        return NULL;
    }
    manager->path = flb_sds_create(root_path);
    manager->limit = ctx->buffer_dir_limit_size;
    manager->references = 1;
    manager->lock_fd = -1;
    mk_list_init(&manager->instance_leases);
    pthread_mutex_init(&manager->mutex, NULL);
    snprintf(db_path, sizeof(db_path), "%s/.azure_logs_ingestion.db", root_path);
    if (manager->path == NULL || lock_manager_root(manager) == -1) {
        flb_plg_error(ctx->ins, "buffer_dir is already owned by another process");
        manager->db = NULL;
    }
    else {
        manager->db = flb_sqldb_open(db_path, "azure logs ingestion spool", ctx->config);
    }
    if (manager->path == NULL || manager->db == NULL || manager_schema(manager) == -1) {
        if (manager->db != NULL) {
            flb_sqldb_close(manager->db);
        }
        unlock_manager_root(manager);
        flb_sds_destroy(manager->path);
        pthread_mutex_destroy(&manager->mutex);
        flb_free(manager);
        pthread_mutex_unlock(&manager_registry_mutex);
        return NULL;
    }

    ret = sqlite3_prepare_v2(manager->db->handler,
            "SELECT disk_limit FROM azli_settings WHERE root=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto error;
    }
    sqlite3_bind_text(statement, 1, manager->path, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        stored_limit = sqlite3_column_int64(statement, 0);
        ret = sqlite3_step(statement);
        sqlite3_finalize(statement);
        statement = NULL;
        if (ret != SQLITE_DONE) {
            goto error;
        }
        if (stored_limit != (int64_t) manager->limit) {
            ret = sqlite3_prepare_v2(manager->db->handler,
                    "UPDATE azli_settings SET disk_limit=? WHERE root=?", -1,
                    &statement, NULL);
            if (ret != SQLITE_OK) {
                goto error;
            }
            sqlite3_bind_int64(statement, 1, manager->limit);
            sqlite3_bind_text(statement, 2, manager->path, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(statement) != SQLITE_DONE) {
                goto error;
            }
            sqlite3_finalize(statement);
            statement = NULL;
        }
    }
    else if (ret == SQLITE_DONE) {
        sqlite3_finalize(statement);
        statement = NULL;
        ret = sqlite3_prepare_v2(manager->db->handler,
                "INSERT INTO azli_settings(root,disk_limit) VALUES(?,?)", -1,
                &statement, NULL);
        if (ret != SQLITE_OK) {
            goto error;
        }
        sqlite3_bind_text(statement, 1, manager->path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 2, manager->limit);
        if (sqlite3_step(statement) != SQLITE_DONE) {
            goto error;
        }
        sqlite3_finalize(statement);
        statement = NULL;
    }
    else {
        goto error;
    }
    if (manager_validate_invariants(manager) == -1 ||
        manager_configure_limits(manager) == -1 ||
        manager_maintain(manager, FLB_TRUE) < 0) {
        goto error;
    }
    if (manager->physical_used > manager->limit) {
        flb_plg_error(ctx->ins,
                      "SQLite spool exceeds physical limit used=%zu limit=%zu",
                      manager->physical_used, manager->limit);
        goto error;
    }
    mk_list_add(&manager->_head, &manager_registry);
    pthread_mutex_unlock(&manager_registry_mutex);
    return manager;

error:
    sqlite3_finalize(statement);
    flb_sqldb_close(manager->db);
    unlock_manager_root(manager);
    flb_sds_destroy(manager->path);
    pthread_mutex_destroy(&manager->mutex);
    flb_free(manager);
    pthread_mutex_unlock(&manager_registry_mutex);
    return NULL;
}

static void manager_release(struct azli_root_manager *manager)
{
    pthread_mutex_lock(&manager_registry_mutex);
    manager->references--;
    if (manager->references > 0) {
        pthread_mutex_unlock(&manager_registry_mutex);
        return;
    }
    mk_list_del(&manager->_head);
    flb_sqldb_close(manager->db);
    unlock_manager_root(manager);
    flb_sds_destroy(manager->path);
    pthread_mutex_destroy(&manager->mutex);
    flb_free(manager);
    pthread_mutex_unlock(&manager_registry_mutex);
}

static int manager_claim_instance(struct flb_az_li *ctx)
{
    struct azli_instance_lease *lease;
    struct mk_list *head;

    mk_list_foreach(head, &ctx->batch->manager->instance_leases) {
        lease = mk_list_entry(head, struct azli_instance_lease, _head);
        if (strcmp(lease->instance_key, ctx->buffer_key) == 0) {
            flb_plg_error(ctx->ins,
                          "buffer_key is already active in this process key=%s",
                          ctx->buffer_key);
            return -1;
        }
    }
    lease = flb_calloc(1, sizeof(*lease));
    if (lease == NULL) {
        return -1;
    }
    lease->instance_key = flb_sds_create(ctx->buffer_key);
    if (lease->instance_key == NULL) {
        flb_free(lease);
        return -1;
    }
    mk_list_add(&lease->_head, &ctx->batch->manager->instance_leases);
    ctx->batch->lease = lease;
    return 0;
}

static void manager_release_instance(struct flb_az_li_batch *batch)
{
    if (batch->lease == NULL) {
        return;
    }
    mk_list_del(&batch->lease->_head);
    flb_sds_destroy(batch->lease->instance_key);
    flb_free(batch->lease);
    batch->lease = NULL;
}

static int instance_attach(struct flb_az_li *ctx)
{
    flb_sds_t value;
    unsigned char digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    int ret;

    value = flb_sds_create_size(strlen(ctx->dce_url) + strlen(ctx->dcr_id) +
                                strlen(ctx->table_name) + strlen(ctx->time_key) + 64);
    if (value == NULL) {
        return -1;
    }
    value = flb_sds_printf(&value, "%s\n%s\n%s\n%s\n%d", ctx->dce_url,
                           ctx->dcr_id, ctx->table_name, ctx->time_key,
                           ctx->time_generated);
    if (value == NULL || hash_bytes(value, flb_sds_len(value), digest) != 0) {
        flb_sds_destroy(value);
        return -1;
    }
    flb_sds_destroy(value);

    statement = NULL;
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT destination FROM azli_instances WHERE instance_key=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        ret = sqlite3_column_bytes(statement, 0) == AZLI_DIGEST_SIZE &&
              memcmp(sqlite3_column_blob(statement, 0), digest,
                     AZLI_DIGEST_SIZE) == 0 ? 0 : -1;
        if (sqlite3_step(statement) != SQLITE_DONE) {
            ret = -1;
        }
        sqlite3_finalize(statement);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "buffer_key belongs to a different destination");
        }
        return ret;
    }
    if (ret != SQLITE_DONE) {
        sqlite3_finalize(statement);
        return -1;
    }
    sqlite3_finalize(statement);

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "INSERT INTO azli_instances(instance_key,destination) VALUES(?,?)", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(statement, 2, digest, AZLI_DIGEST_SIZE, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    return ret;
}

static int cleanup_expired_receipts(struct azli_root_manager *manager)
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(manager->db->handler,
            "DELETE FROM azli_receipts WHERE expires<=? "
            "AND NOT EXISTS (SELECT 1 FROM azli_sources s "
            "WHERE s.instance_key=azli_receipts.instance_key "
            "AND s.source_id=azli_receipts.source_id)", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, now_seconds());
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    return ret;
}

static int source_content_validate(const void *data, size_t size)
{
    const char *bytes;

    if (data == NULL || size < 2) {
        return -1;
    }
    bytes = data;
    if (bytes[0] != '[' || bytes[size - 1] != ']') {
        return -1;
    }
    return 0;
}

static int source_quarantine(struct flb_az_li *ctx, int64_t source_pk,
                             const char *reason)
{
    sqlite3_stmt *statement;
    int64_t record_count;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT record_count FROM azli_sources WHERE source_pk=? "
            "AND instance_key=? AND state=? AND request_pk IS NULL", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, source_pk);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 3, AZLI_SOURCE_READY);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    record_count = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_sources SET state=?,quarantine_reason=? "
            "WHERE source_pk=? AND instance_key=? AND state=? "
            "AND request_pk IS NULL", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(statement, 1, AZLI_SOURCE_QUARANTINED);
    sqlite3_bind_text(statement, 2, reason, -1, SQLITE_STATIC);
    sqlite3_bind_int64(statement, 3, source_pk);
    sqlite3_bind_text(statement, 4, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 5, AZLI_SOURCE_READY);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    if (ret == 0 && sqlite3_changes(ctx->batch->manager->db->handler) == 1) {
        metric_counter_add(ctx, ctx->cmt_quarantined_chunks, 1.0);
        metric_counter_add(ctx, ctx->cmt_quarantined_records,
                           (double) record_count);
    }
    sqlite3_finalize(statement);
    return ret;
}

static int receipt_or_source_exists(struct flb_az_li *ctx, const char *source_id,
                                    const unsigned char digest[32])
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT digest FROM azli_sources WHERE instance_key=? AND source_id=? "
            "UNION ALL SELECT digest FROM azli_receipts "
            "WHERE instance_key=? AND source_id=?", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return AZLI_SOURCE_EXISTS_ERROR;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, source_id, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        ret = sqlite3_column_bytes(statement, 0) == AZLI_DIGEST_SIZE &&
              memcmp(sqlite3_column_blob(statement, 0), digest,
                     AZLI_DIGEST_SIZE) == 0 ? AZLI_SOURCE_EXISTS_MATCH :
                                             AZLI_SOURCE_EXISTS_COLLISION;
    }
    else if (ret == SQLITE_DONE) {
        ret = AZLI_SOURCE_EXISTS_NONE;
    }
    else {
        ret = AZLI_SOURCE_EXISTS_ERROR;
    }
    sqlite3_finalize(statement);
    return ret;
}

static int source_identity(struct flb_az_li *ctx,
                           struct flb_output_flush *out_flush,
                           char output[AZLI_HEX_SIZE + 1])
{
    flb_sds_t chunk_name;
    flb_sds_t key;
    const char *input_name;
    unsigned char digest[AZLI_DIGEST_SIZE];

    if (out_flush == NULL || out_flush->task == NULL ||
        out_flush->task->ic == NULL || out_flush->task->i_ins == NULL ||
        out_flush->task->i_ins->name[0] == '\0') {
        flb_plg_error(ctx->ins, "input chunk has no durable name");
        return -1;
    }
    chunk_name = flb_input_chunk_get_name(
                    (struct flb_input_chunk *) out_flush->task->ic);
    if (chunk_name == NULL || strlen(chunk_name) == 0) {
        flb_plg_error(ctx->ins, "input chunk has no durable name");
        return -1;
    }
    input_name = out_flush->task->i_ins->name;
    key = flb_sds_create_size(strlen(ctx->buffer_key) + strlen(input_name) +
                              strlen(chunk_name) + 64);
    if (key == NULL) {
        return -1;
    }
    key = flb_sds_printf(&key, "%s\n%s\n%s", ctx->buffer_key,
                         input_name, chunk_name);
    if (key == NULL) {
        flb_plg_error(ctx->ins, "cannot allocate input chunk identity");
        return -1;
    }
    if (hash_bytes(key, flb_sds_len(key), digest) != 0) {
        flb_plg_error(ctx->ins, "cannot hash input chunk identity");
        flb_sds_destroy(key);
        return -1;
    }
    flb_sds_destroy(key);
    digest_hex(digest, output);
    return 0;
}


static int validate_source_blob(struct flb_az_li *ctx, int64_t source_pk)
{
    unsigned char digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    const void *content;
    const void *stored_digest;
    int content_size;
    int digest_size;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT content,digest,json_bytes,record_count,bytes,created,source_id,name "
            "FROM azli_sources WHERE source_pk=? AND instance_key=? AND state=? "
            "AND request_pk IS NULL", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, source_pk);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 3, AZLI_SOURCE_READY);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_DONE) {
        sqlite3_finalize(statement);
        return 0;
    }
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    content = sqlite3_column_blob(statement, 0);
    content_size = sqlite3_column_bytes(statement, 0);
    stored_digest = sqlite3_column_blob(statement, 1);
    digest_size = sqlite3_column_bytes(statement, 1);
    if (content_size < 2 || sqlite3_column_int64(statement, 2) != content_size ||
        sqlite3_column_int64(statement, 3) <= 0 ||
        sqlite3_column_int64(statement, 4) < content_size ||
        sqlite3_column_int64(statement, 5) <= 0 ||
        sqlite3_column_text(statement, 6) == NULL ||
        strlen((const char *) sqlite3_column_text(statement, 6)) != AZLI_HEX_SIZE ||
        sqlite3_column_text(statement, 7) == NULL ||
        sqlite3_column_bytes(statement, 7) == 0 ||
        digest_size != AZLI_DIGEST_SIZE ||
        source_content_validate(content, (size_t) content_size) == -1 ||
        hash_bytes(content, (size_t) content_size, digest) != 0 ||
        memcmp(digest, stored_digest, AZLI_DIGEST_SIZE) != 0) {
        sqlite3_finalize(statement);
        flb_plg_error(ctx->ins, "quarantining corrupt source row=%" PRId64,
                      source_pk);
        return source_quarantine(ctx, source_pk, "content_corrupt");
    }
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return ret == SQLITE_DONE ? 0 : -1;
}

static int validate_source_rows(struct flb_az_li *ctx)
{
    int64_t *source_pks;
    sqlite3_stmt *statement;
    size_t count;
    size_t index;
    int ret;

    source_pks = flb_calloc(AZLI_MAX_SOURCE_FILES, sizeof(*source_pks));
    if (source_pks == NULL) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT source_pk FROM azli_sources WHERE instance_key=? "
            "AND state=? AND request_pk IS NULL ORDER BY source_pk", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        flb_free(source_pks);
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_SOURCE_READY);
    count = 0;
    while ((ret = sqlite3_step(statement)) == SQLITE_ROW) {
        if (count >= AZLI_MAX_SOURCE_FILES) {
            sqlite3_finalize(statement);
            flb_free(source_pks);
            return -1;
        }
        source_pks[count++] = sqlite3_column_int64(statement, 0);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        flb_free(source_pks);
        return -1;
    }
    for (index = 0; index < count; index++) {
        if (validate_source_blob(ctx, source_pks[index]) == -1) {
            flb_free(source_pks);
            return -1;
        }
    }
    flb_free(source_pks);
    return 0;
}

static int repair_acked_receipts(struct flb_az_li *ctx)
{
    unsigned char digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    const void *content;
    const void *stored_digest;
    int64_t completed;
    int content_size;
    int missing;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT s.content,s.digest,s.json_bytes,s.record_count,s.source_id "
            "FROM azli_sources s JOIN azli_requests r "
            "ON r.request_pk=s.request_pk AND r.instance_key=s.instance_key "
            "WHERE s.instance_key=? AND s.state=? AND r.state=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_SOURCE_DRAINED);
    sqlite3_bind_int(statement, 3, AZLI_REQUEST_ACKED);
    while ((ret = sqlite3_step(statement)) == SQLITE_ROW) {
        content = sqlite3_column_blob(statement, 0);
        content_size = sqlite3_column_bytes(statement, 0);
        stored_digest = sqlite3_column_blob(statement, 1);
        if (content_size < 2 || sqlite3_column_bytes(statement, 1) != AZLI_DIGEST_SIZE ||
            sqlite3_column_int64(statement, 2) != content_size ||
            sqlite3_column_int64(statement, 3) <= 0 ||
            sqlite3_column_text(statement, 4) == NULL ||
            strlen((const char *) sqlite3_column_text(statement, 4)) != AZLI_HEX_SIZE ||
            source_content_validate(content, (size_t) content_size) == -1 ||
            hash_bytes(content, (size_t) content_size, digest) != 0 ||
            memcmp(digest, stored_digest, AZLI_DIGEST_SIZE) != 0) {
            sqlite3_finalize(statement);
            return -1;
        }
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE ||
        sql_exec(ctx->batch->manager, "BEGIN IMMEDIATE") == -1) {
        return -1;
    }
    completed = now_seconds();
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT COUNT(*) FROM azli_sources s JOIN azli_requests r "
            "ON r.request_pk=s.request_pk AND r.instance_key=s.instance_key "
            "JOIN azli_receipts p ON p.instance_key=s.instance_key "
            "AND p.source_id=s.source_id WHERE s.instance_key=? AND s.state=? "
            "AND r.state=? AND p.digest!=s.digest", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        goto repair_rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_SOURCE_DRAINED);
    sqlite3_bind_int(statement, 3, AZLI_REQUEST_ACKED);
    if (sqlite3_step(statement) != SQLITE_ROW || sqlite3_column_int(statement, 0) != 0 ||
        sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        goto repair_rollback;
    }
    sqlite3_finalize(statement);
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "INSERT OR IGNORE INTO azli_receipts(instance_key,source_id,digest,"
            "completed,expires,bytes) SELECT s.instance_key,s.source_id,s.digest,?,?,? "
            "FROM azli_sources s JOIN azli_requests r "
            "ON r.request_pk=s.request_pk AND r.instance_key=s.instance_key "
            "WHERE s.instance_key=? AND s.state=? AND r.state=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto repair_rollback;
    }
    sqlite3_bind_int64(statement, 1, completed);
    sqlite3_bind_int64(statement, 2,
                       completed + (int64_t) ctx->buffer_receipt_ttl);
    sqlite3_bind_int64(statement, 3, AZLI_RECEIPT_DB_RESERVE);
    sqlite3_bind_text(statement, 4, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 5, AZLI_SOURCE_DRAINED);
    sqlite3_bind_int(statement, 6, AZLI_REQUEST_ACKED);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        goto repair_rollback;
    }
    sqlite3_finalize(statement);
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT COUNT(*) FROM azli_sources s JOIN azli_requests r "
            "ON r.request_pk=s.request_pk AND r.instance_key=s.instance_key "
            "LEFT JOIN azli_receipts p ON p.instance_key=s.instance_key "
            "AND p.source_id=s.source_id AND p.digest=s.digest "
            "WHERE s.instance_key=? AND s.state=? AND r.state=? "
            "AND p.source_id IS NULL", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        goto repair_rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_SOURCE_DRAINED);
    sqlite3_bind_int(statement, 3, AZLI_REQUEST_ACKED);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        goto repair_rollback;
    }
    missing = sqlite3_column_int(statement, 0);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE || missing != 0) {
        goto repair_rollback;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_instances SET last_success=MAX(last_success,COALESCE(("
            "SELECT MAX(completed) FROM azli_receipts WHERE instance_key=?),0)) "
            "WHERE instance_key=?", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        goto repair_rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE ||
        sqlite3_changes(ctx->batch->manager->db->handler) != 1) {
        sqlite3_finalize(statement);
        goto repair_rollback;
    }
    sqlite3_finalize(statement);
    ret = sql_commit(ctx->batch->manager);
    if (ret == 0) {
        return 0;
    }
    if (ret == 1 && sqlite3_get_autocommit(ctx->batch->manager->db->handler) != 0) {
        return repair_acked_receipts(ctx);
    }
    return -1;

repair_rollback:
    sql_rollback_if_active(ctx->batch->manager);
    return -1;
}

static int acknowledged_cleanup_complete(struct flb_az_li *ctx)
{
    sqlite3_stmt *statement;
    int count;
    int ret;

    if (sqlite3_get_autocommit(ctx->batch->manager->db->handler) == 0) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT (SELECT COUNT(*) FROM azli_sources WHERE instance_key=? "
            "AND state=?) + (SELECT COUNT(*) FROM azli_requests "
            "WHERE instance_key=? AND state=?)", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_SOURCE_DRAINED);
    sqlite3_bind_text(statement, 3, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 4, AZLI_REQUEST_ACKED);
    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    count = sqlite3_column_int(statement, 0);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return ret == SQLITE_DONE && count == 0 ? 1 : 0;
}

static int cleanup_acknowledged(struct flb_az_li *ctx)
{
    sqlite3_stmt *statement;
    int ret;

    if (repair_acked_receipts(ctx) == -1 ||
        sql_exec(ctx->batch->manager, "BEGIN IMMEDIATE") == -1) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "DELETE FROM azli_sources WHERE instance_key=? AND state=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_SOURCE_DRAINED);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        goto rollback;
    }
    sqlite3_finalize(statement);
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "DELETE FROM azli_requests WHERE instance_key=? AND state=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_REQUEST_ACKED);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        goto rollback;
    }
    sqlite3_finalize(statement);
    ret = sql_commit(ctx->batch->manager);
    if (ret != 0 &&
        (ret != 1 || acknowledged_cleanup_complete(ctx) != 1)) {
        return -1;
    }
    return manager_recount(ctx->batch->manager);

rollback:
    sql_rollback_if_active(ctx->batch->manager);
    return -1;
}

static int request_outcome_matches(struct flb_az_li *ctx, int64_t request_pk,
                                   int quarantine)
{
    sqlite3_stmt *statement;
    int expected_request_state;
    int expected_source_state;
    int64_t member_count;
    int64_t state_count;
    int64_t receipt_count;
    int64_t last_success;
    int64_t latest_receipt;
    int ret;

    if (sqlite3_get_autocommit(ctx->batch->manager->db->handler) == 0) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT r.state,"
            "(SELECT COUNT(*) FROM azli_sources s WHERE s.request_pk=r.request_pk "
            " AND s.instance_key=r.instance_key),"
            "(SELECT COUNT(*) FROM azli_sources s WHERE s.request_pk=r.request_pk "
            " AND s.instance_key=r.instance_key AND s.state=?),"
            "(SELECT COUNT(*) FROM azli_sources s JOIN azli_receipts p "
            " ON p.instance_key=s.instance_key AND p.source_id=s.source_id "
            " AND p.digest=s.digest WHERE s.request_pk=r.request_pk "
            " AND s.instance_key=r.instance_key),"
            "(SELECT i.last_success FROM azli_instances i "
            " WHERE i.instance_key=r.instance_key),"
            "(SELECT COALESCE(MAX(p.completed),0) FROM azli_sources s "
            " JOIN azli_receipts p ON p.instance_key=s.instance_key "
            " AND p.source_id=s.source_id AND p.digest=s.digest "
            " WHERE s.request_pk=r.request_pk AND s.instance_key=r.instance_key) "
            "FROM azli_requests r WHERE r.request_pk=? AND r.instance_key=?",
            -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    expected_request_state = quarantine ? AZLI_REQUEST_QUARANTINED :
                                          AZLI_REQUEST_ACKED;
    expected_source_state = quarantine ? AZLI_SOURCE_QUARANTINED :
                                         AZLI_SOURCE_DRAINED;
    sqlite3_bind_int(statement, 1, expected_source_state);
    sqlite3_bind_int64(statement, 2, request_pk);
    sqlite3_bind_text(statement, 3, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        member_count = sqlite3_column_int64(statement, 1);
        state_count = sqlite3_column_int64(statement, 2);
        receipt_count = sqlite3_column_int64(statement, 3);
        last_success = sqlite3_column_int64(statement, 4);
        latest_receipt = sqlite3_column_int64(statement, 5);
        ret = sqlite3_column_int(statement, 0) == expected_request_state &&
              member_count > 0 && state_count == member_count &&
              (quarantine || (receipt_count == member_count &&
                              latest_receipt > 0 &&
                              last_success >= latest_receipt)) ? 1 : 0;
    }
    else if (ret == SQLITE_DONE) {
        ret = 0;
    }
    else {
        ret = -1;
    }
    sqlite3_finalize(statement);
    return ret;
}

static int validate_request_members(struct flb_az_li *ctx, int64_t request_pk,
                                    unsigned char json_digest[AZLI_DIGEST_SIZE])
{
    unsigned char digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    const void *content;
    const void *stored_digest;
    const unsigned char *source_id;
    const unsigned char *name;
    flb_sds_t json;
    flb_sds_t tmp;
    int content_size;
    int count;
    int ret;

    json = flb_sds_create("[");
    if (json == NULL) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT source_id,name,digest,content,record_count,json_bytes,bytes,"
            "created,state,EXISTS(SELECT 1 FROM azli_receipts p WHERE "
            "p.instance_key=azli_sources.instance_key AND "
            "p.source_id=azli_sources.source_id) "
            "FROM azli_sources WHERE request_pk=? AND instance_key=? "
            "ORDER BY source_pk", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        flb_sds_destroy(json);
        return -1;
    }
    sqlite3_bind_int64(statement, 1, request_pk);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    count = 0;
    while ((ret = sqlite3_step(statement)) == SQLITE_ROW) {
        source_id = sqlite3_column_text(statement, 0);
        name = sqlite3_column_text(statement, 1);
        stored_digest = sqlite3_column_blob(statement, 2);
        content = sqlite3_column_blob(statement, 3);
        content_size = sqlite3_column_bytes(statement, 3);
        if (sqlite3_column_int(statement, 9) != 0) {
            sqlite3_finalize(statement);
            flb_sds_destroy(json);
            return 2;
        }
        if (source_id == NULL || strlen((const char *) source_id) != AZLI_HEX_SIZE ||
            name == NULL || name[0] == '\0' ||
            sqlite3_column_bytes(statement, 2) != AZLI_DIGEST_SIZE ||
            content_size < 2 || sqlite3_column_int64(statement, 4) <= 0 ||
            sqlite3_column_int64(statement, 5) != content_size ||
            sqlite3_column_int64(statement, 6) < content_size ||
            sqlite3_column_int64(statement, 7) <= 0 ||
            sqlite3_column_int(statement, 8) != AZLI_SOURCE_READY ||
            source_content_validate(content, (size_t) content_size) == -1 ||
            hash_bytes(content, (size_t) content_size, digest) != 0 ||
            memcmp(digest, stored_digest, AZLI_DIGEST_SIZE) != 0) {
            sqlite3_finalize(statement);
            flb_sds_destroy(json);
            return 1;
        }
        if (count > 0) {
            tmp = flb_sds_cat(json, ",", 1);
            if (tmp == NULL) {
                sqlite3_finalize(statement);
                flb_sds_destroy(json);
                return -1;
            }
            json = tmp;
        }
        tmp = flb_sds_cat(json, (const char *) content + 1,
                          (size_t) content_size - 2);
        if (tmp == NULL) {
            sqlite3_finalize(statement);
            flb_sds_destroy(json);
            return -1;
        }
        json = tmp;
        count++;
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE || count == 0) {
        flb_sds_destroy(json);
        return ret == SQLITE_DONE ? 1 : -1;
    }
    tmp = flb_sds_cat(json, "]", 1);
    if (tmp == NULL) {
        flb_sds_destroy(json);
        return -1;
    }
    json = tmp;
    ret = hash_bytes(json, flb_sds_len(json), json_digest);
    flb_sds_destroy(json);
    return ret == 0 ? 0 : -1;
}

static int validate_request_blob(struct flb_az_li *ctx, int64_t request_pk)
{
    struct azli_request request;
    unsigned char digest[AZLI_DIGEST_SIZE];
    unsigned char member_digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    const void *body;
    const void *stored_digest;
    const void *stored_json_digest;
    void *uncompressed;
    size_t uncompressed_size;
    int body_size;
    int ret;

    memset(&request, 0, sizeof(request));
    uncompressed = NULL;
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT name,state,gzip_bytes,body,body_digest,json_digest,json_bytes "
            "FROM azli_requests WHERE request_pk=? AND instance_key=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, request_pk);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return ret == SQLITE_DONE ? 0 : -1;
    }
    request.request_pk = request_pk;
    request.state = sqlite3_column_int(statement, 1);
    request.name = flb_sds_create((const char *) sqlite3_column_text(statement, 0));
    body_size = sqlite3_column_bytes(statement, 3);
    body = sqlite3_column_blob(statement, 3);
    stored_digest = sqlite3_column_blob(statement, 4);
    stored_json_digest = sqlite3_column_blob(statement, 5);
    if (request.name == NULL || body_size < 0 ||
        sqlite3_column_int64(statement, 2) != body_size ||
        sqlite3_column_bytes(statement, 4) != AZLI_DIGEST_SIZE ||
        sqlite3_column_bytes(statement, 5) != AZLI_DIGEST_SIZE ||
        sqlite3_column_int64(statement, 6) < 2 ||
        (size_t) body_size > FLB_AZ_LI_MAX_REQUEST_SIZE ||
        hash_bytes(body, (size_t) body_size, digest) != 0 ||
        memcmp(digest, stored_digest, AZLI_DIGEST_SIZE) != 0 ||
        flb_gzip_uncompress((void *) body, (size_t) body_size,
                            &uncompressed, &uncompressed_size) != 0 ||
        uncompressed_size != (size_t) sqlite3_column_int64(statement, 6) ||
        hash_bytes(uncompressed, uncompressed_size, digest) != 0 ||
        memcmp(digest, stored_json_digest, AZLI_DIGEST_SIZE) != 0) {
        flb_free(uncompressed);
        sqlite3_finalize(statement);
        if (request.name == NULL) {
            return -1;
        }
        flb_plg_error(ctx->ins, "quarantining corrupt request name=%s",
                      request.name);
        ret = request_commit_sources(ctx, &request, FLB_TRUE, 0,
                                     "artifact_corrupt");
        flb_sds_destroy(request.name);
        return ret;
    }
    memcpy(request.json_digest, stored_json_digest, AZLI_DIGEST_SIZE);
    flb_free(uncompressed);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        flb_sds_destroy(request.name);
        return -1;
    }
    ret = validate_request_members(ctx, request_pk, member_digest);
    if (ret == 0 && memcmp(member_digest, request.json_digest,
                           AZLI_DIGEST_SIZE) != 0) {
        ret = 1;
    }
    if (ret == 1) {
        flb_plg_error(ctx->ins,
                      "quarantining request with mismatched source membership name=%s",
                      request.name);
        ret = request_commit_sources(ctx, &request, FLB_TRUE, 0,
                                     "source_membership_mismatch");
    }
    flb_sds_destroy(request.name);
    return ret;
}

static int validate_request_rows(struct flb_az_li *ctx)
{
    int64_t *request_pks;
    sqlite3_stmt *statement;
    size_t count;
    size_t index;
    int ret;

    request_pks = flb_calloc(AZLI_MAX_SOURCE_FILES, sizeof(*request_pks));
    if (request_pks == NULL) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT request_pk FROM azli_requests WHERE instance_key=? "
            "AND state IN (1,2,3) ORDER BY request_pk", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        flb_free(request_pks);
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    count = 0;
    while ((ret = sqlite3_step(statement)) == SQLITE_ROW) {
        if (count >= AZLI_MAX_SOURCE_FILES) {
            sqlite3_finalize(statement);
            flb_free(request_pks);
            return -1;
        }
        request_pks[count++] = sqlite3_column_int64(statement, 0);
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        flb_free(request_pks);
        return -1;
    }
    for (index = 0; index < count; index++) {
        if (validate_request_blob(ctx, request_pks[index]) != 0) {
            flb_free(request_pks);
            return -1;
        }
    }
    flb_free(request_pks);
    return 0;
}

static int recover_requests(struct flb_az_li *ctx)
{
    sqlite3_stmt *statement;
    int ret;

    if (cleanup_acknowledged(ctx) == -1 || validate_request_rows(ctx) == -1) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_requests SET state=?,next_retry=0 WHERE instance_key=? "
            "AND state=?", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(statement, 1, AZLI_REQUEST_RETRY);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 3, AZLI_REQUEST_INFLIGHT);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    return ret;
}

static int source_manifest_matches(struct flb_az_li *ctx,
                                   const char *source_id, const char *name,
                                   const unsigned char digest[AZLI_DIGEST_SIZE],
                                   size_t record_count, size_t json_size,
                                   size_t gzip_size, int64_t created)
{
    unsigned char actual_digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    const void *content;
    int content_size;
    int ret;

    if (sqlite3_get_autocommit(ctx->batch->manager->db->handler) == 0) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT name,digest,content,record_count,json_bytes,standalone_gzip_bytes,"
            "created,state,request_pk "
            "FROM azli_sources WHERE instance_key=? AND source_id=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        content = sqlite3_column_blob(statement, 2);
        content_size = sqlite3_column_bytes(statement, 2);
        ret = content_size == (int) json_size &&
              hash_bytes(content, json_size, actual_digest) == 0 &&
              strcmp((const char *) sqlite3_column_text(statement, 0), name) == 0 &&
              sqlite3_column_bytes(statement, 1) == AZLI_DIGEST_SIZE &&
              memcmp(sqlite3_column_blob(statement, 1), digest,
                     AZLI_DIGEST_SIZE) == 0 &&
              memcmp(actual_digest, digest, AZLI_DIGEST_SIZE) == 0 &&
              sqlite3_column_int64(statement, 3) == (int64_t) record_count &&
              sqlite3_column_int64(statement, 4) == (int64_t) json_size &&
              sqlite3_column_int64(statement, 5) == (int64_t) gzip_size &&
              sqlite3_column_int64(statement, 6) == created &&
              sqlite3_column_int(statement, 7) == AZLI_SOURCE_READY &&
              sqlite3_column_type(statement, 8) == SQLITE_NULL ? 1 : -1;
    }
    else if (ret == SQLITE_DONE) {
        ret = 0;
    }
    else {
        ret = -1;
    }
    sqlite3_finalize(statement);
    return ret;
}

static int admission_has_capacity(struct flb_az_li *ctx, size_t incoming)
{
    struct azli_root_manager *manager;
    size_t headroom;

    manager = ctx->batch->manager;
    headroom = FLB_AZ_LI_MAX_REQUEST_SIZE + AZLI_REQUEST_DB_RESERVE +
               AZLI_MAX_REQUEST_SOURCES * AZLI_MEMBER_DB_RESERVE;
    if (manager_recount(manager) == -1) {
        return -1;
    }
    if (headroom <= manager->limit && incoming <= manager->limit - headroom &&
        manager->reserved_bytes <= manager->limit - headroom - incoming &&
        manager->logical_used <= manager->limit - headroom - incoming -
                                 manager->reserved_bytes &&
        manager_has_physical_capacity(manager, incoming) == 1) {
        return 1;
    }
    if (cleanup_expired_receipts(ctx->batch->manager) == -1 ||
        manager_maintain(manager, FLB_TRUE) < 0) {
        return -1;
    }
    if (headroom > manager->limit || incoming > manager->limit - headroom ||
        manager->reserved_bytes > manager->limit - headroom - incoming ||
        manager->logical_used > manager->limit - headroom - incoming -
                                manager->reserved_bytes ||
        manager_has_physical_capacity(manager, incoming) != 1) {
        return 0;
    }
    return 1;
}

int az_li_batch_admit_chunk(struct flb_az_li *ctx,
                            struct flb_output_flush *out_flush,
                            const void *json, size_t json_size,
                            size_t record_count)
{
    char source_id[AZLI_HEX_SIZE + 1];
    char name[80];
    unsigned char digest[AZLI_DIGEST_SIZE];
    void *gzip;
    size_t gzip_size;
    sqlite3_stmt *statement;
    size_t charged_bytes;
    int64_t created;
    int capacity;
    int exists;
    int rollback_ret;
    int recount_failed;
    int ret;

    gzip = NULL;
    recount_failed = FLB_FALSE;
    pthread_mutex_lock(&ctx->batch->lifecycle_mutex);
    if (ctx->batch->shutting_down || ctx->batch->fatal_error) {
        pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
        return -1;
    }
    pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
    if (record_count == 0) {
        return 0;
    }
    if (source_identity(ctx, out_flush, source_id) == -1 ||
        source_content_validate(json, json_size) == -1 ||
        hash_bytes(json, json_size, digest) != 0) {
        return -1;
    }
    if (json_size > ctx->batch_max_uncompressed_size) {
        flb_plg_error(ctx->ins,
                      "input chunk exceeds uncompressed request limit id=%s bytes=%zu limit=%zu",
                      source_id, json_size, ctx->batch_max_uncompressed_size);
        return -1;
    }
    if (flb_gzip_compress((void *) json, json_size, &gzip, &gzip_size) == -1) {
        return -1;
    }
    flb_free(gzip);
    if (gzip_size > FLB_AZ_LI_MAX_REQUEST_SIZE) {
        flb_plg_error(ctx->ins,
                      "input chunk exceeds compressed request limit id=%s bytes=%zu limit=%d",
                      source_id, gzip_size, FLB_AZ_LI_MAX_REQUEST_SIZE);
        return -1;
    }
    if (json_size > SIZE_MAX - AZLI_SOURCE_DB_RESERVE -
                    AZLI_RECEIPT_DB_RESERVE) {
        return -1;
    }
    charged_bytes = json_size + AZLI_SOURCE_DB_RESERVE +
                    AZLI_RECEIPT_DB_RESERVE;
    created = now_seconds();
    snprintf(name, sizeof(name), "%s.source", source_id);

    pthread_mutex_lock(&ctx->batch->manager->mutex);
    exists = receipt_or_source_exists(ctx, source_id, digest);
    if (exists != AZLI_SOURCE_EXISTS_NONE) {
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        if (exists == AZLI_SOURCE_EXISTS_ERROR) {
            flb_plg_error(ctx->ins,
                          "could not query durable input chunk identity id=%s",
                          source_id);
            metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
            return -1;
        }
        if (exists == AZLI_SOURCE_EXISTS_COLLISION) {
            flb_plg_error(ctx->ins, "input chunk identity collision id=%s", source_id);
            return -1;
        }
        flb_plg_debug(ctx->ins, "input chunk already durably owned id=%s", source_id);
        return 0;
    }
    capacity = admission_has_capacity(ctx, charged_bytes);
    if (capacity <= 0 || ctx->batch->manager->files >= AZLI_MAX_SOURCE_FILES) {
        if (capacity == 0) {
            flb_plg_error(ctx->ins,
                          "batch buffer full logical=%zu physical=%zu incoming=%zu limit=%zu",
                          ctx->batch->manager->logical_used,
                          ctx->batch->manager->physical_used, charged_bytes,
                          ctx->batch->manager->limit);
            metric_counter_add(ctx, ctx->cmt_quota_rejections, 1.0);
        }
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        if (capacity < 0) {
            metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
        }
        return -1;
    }

    statement = NULL;
    if (sql_exec(ctx->batch->manager, "BEGIN IMMEDIATE") == -1) {
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "INSERT INTO azli_sources(instance_key,source_id,name,digest,content,"
            "record_count,json_bytes,standalone_gzip_bytes,bytes,created,state,request_pk) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob64(statement, 4, digest, AZLI_DIGEST_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_blob64(statement, 5, json, json_size, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 6, record_count);
    sqlite3_bind_int64(statement, 7, json_size);
    sqlite3_bind_int64(statement, 8, gzip_size);
    sqlite3_bind_int64(statement, 9, charged_bytes);
    sqlite3_bind_int64(statement, 10, created);
    sqlite3_bind_int(statement, 11, AZLI_SOURCE_READY);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        goto rollback;
    }
    sqlite3_finalize(statement);
    statement = NULL;
    ret = sql_commit(ctx->batch->manager);
    if (ret != 0) {
        if (ret != 1 ||
            sqlite3_get_autocommit(ctx->batch->manager->db->handler) == 0) {
            pthread_mutex_lock(&ctx->batch->lifecycle_mutex);
            ctx->batch->fatal_error = FLB_TRUE;
            ctx->batch->persistence_degraded = FLB_TRUE;
            ctx->batch->next_recovery = now_seconds() + 1;
            pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
            pthread_mutex_unlock(&ctx->batch->manager->mutex);
            metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
            return -1;
        }
        ret = source_manifest_matches(ctx, source_id, name, digest,
                                      record_count, json_size, gzip_size, created);
        if (ret != 1) {
            pthread_mutex_lock(&ctx->batch->lifecycle_mutex);
            ctx->batch->fatal_error = FLB_TRUE;
            ctx->batch->persistence_degraded = FLB_TRUE;
            ctx->batch->next_recovery = now_seconds() + 1;
            pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
            pthread_mutex_unlock(&ctx->batch->manager->mutex);
            metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
            return -1;
        }
        flb_plg_warn(ctx->ins,
                     "source COMMIT returned an error but durable row was reconciled id=%s",
                     source_id);
    }
    if (manager_recount(ctx->batch->manager) == -1) {
        pthread_mutex_lock(&ctx->batch->lifecycle_mutex);
        ctx->batch->fatal_error = FLB_TRUE;
        ctx->batch->persistence_degraded = FLB_TRUE;
        ctx->batch->next_recovery = now_seconds() + 1;
        pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
        recount_failed = FLB_TRUE;
    }
    metrics_refresh_locked(ctx);
    pthread_mutex_unlock(&ctx->batch->manager->mutex);
    if (recount_failed) {
        metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
    }
    metric_counter_add(ctx, ctx->cmt_admitted_chunks, 1.0);
    metric_counter_add(ctx, ctx->cmt_admitted_records, (double) record_count);
    metric_counter_add(ctx, ctx->cmt_admitted_bytes, (double) json_size);
    flb_plg_debug(ctx->ins,
                  "buffered whole chunk records=%zu json_bytes=%zu gzip_bytes=%zu source=%s",
                  record_count, json_size, gzip_size, source_id);
    return 0;

rollback:
    sqlite3_finalize(statement);
    rollback_ret = sql_rollback_if_active(ctx->batch->manager);
    if (rollback_ret == -1) {
        pthread_mutex_lock(&ctx->batch->lifecycle_mutex);
        ctx->batch->fatal_error = FLB_TRUE;
        ctx->batch->persistence_degraded = FLB_TRUE;
        ctx->batch->next_recovery = now_seconds() + 1;
        pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
    }
    pthread_mutex_unlock(&ctx->batch->manager->mutex);
    metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
    return -1;
}

static void candidate_sources_destroy(struct azli_candidate_source *sources,
                                      size_t count)
{
    size_t index;

    for (index = 0; index < count; index++) {
        flb_free(sources[index].content);
    }
    flb_free(sources);
}

static int load_candidate_sources(struct flb_az_li *ctx,
                                  struct azli_candidate_source **out_sources,
                                  size_t *out_count, int *more_sources)
{
    struct azli_candidate_source *sources;
    sqlite3_stmt *statement;
    size_t count;
    int ret;

    sources = flb_calloc(AZLI_MAX_REQUEST_SOURCES + 1, sizeof(*sources));
    if (sources == NULL) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT source_pk,created,record_count,json_bytes,standalone_gzip_bytes "
            "FROM azli_sources WHERE instance_key=? AND state=? AND request_pk IS NULL "
            "ORDER BY source_pk LIMIT ?", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        flb_free(sources);
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 2, AZLI_SOURCE_READY);
    sqlite3_bind_int(statement, 3, AZLI_MAX_REQUEST_SOURCES + 1);
    count = 0;
    while ((ret = sqlite3_step(statement)) == SQLITE_ROW) {
        sources[count].source_pk = sqlite3_column_int64(statement, 0);
        sources[count].created = sqlite3_column_int64(statement, 1);
        sources[count].record_count = sqlite3_column_int64(statement, 2);
        sources[count].json_bytes = sqlite3_column_int64(statement, 3);
        sources[count].standalone_gzip_bytes = sqlite3_column_int64(statement, 4);
        if (sources[count].source_pk <= 0 || sources[count].created <= 0 ||
            sources[count].record_count <= 0 || sources[count].json_bytes < 2 ||
            sources[count].standalone_gzip_bytes <= 0 ||
            sources[count].standalone_gzip_bytes > FLB_AZ_LI_MAX_REQUEST_SIZE) {
            sqlite3_finalize(statement);
            flb_free(sources);
            return -1;
        }
        count++;
    }
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE) {
        flb_free(sources);
        return -1;
    }
    *more_sources = count > AZLI_MAX_REQUEST_SOURCES;
    if (*more_sources) {
        count = AZLI_MAX_REQUEST_SOURCES;
    }
    *out_sources = sources;
    *out_count = count;
    return 0;
}

static int load_candidate_content(struct flb_az_li *ctx,
                                  struct azli_candidate_source *source)
{
    unsigned char digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    const void *content;
    const void *stored_digest;
    int content_size;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT content,digest,json_bytes,record_count,created,bytes,"
            "standalone_gzip_bytes FROM azli_sources WHERE source_pk=? "
            "AND instance_key=? AND state=? AND request_pk IS NULL", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, source->source_pk);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 3, AZLI_SOURCE_READY);
    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    content = sqlite3_column_blob(statement, 0);
    content_size = sqlite3_column_bytes(statement, 0);
    stored_digest = sqlite3_column_blob(statement, 1);
    if (content_size < 2 || sqlite3_column_bytes(statement, 1) != AZLI_DIGEST_SIZE ||
        sqlite3_column_int64(statement, 2) != content_size ||
        sqlite3_column_int64(statement, 2) != source->json_bytes ||
        sqlite3_column_int64(statement, 3) != source->record_count ||
        sqlite3_column_int64(statement, 4) != source->created ||
        sqlite3_column_int64(statement, 5) < content_size ||
        sqlite3_column_int64(statement, 6) != source->standalone_gzip_bytes ||
        source_content_validate(content, (size_t) content_size) == -1 ||
        hash_bytes(content, (size_t) content_size, digest) != 0 ||
        memcmp(digest, stored_digest, AZLI_DIGEST_SIZE) != 0) {
        sqlite3_finalize(statement);
        if (source_quarantine(ctx, source->source_pk, "content_corrupt") == -1) {
            return -1;
        }
        return -2;
    }
    source->content = flb_malloc((size_t) content_size);
    if (source->content != NULL) {
        memcpy(source->content, content, (size_t) content_size);
        source->content_size = (size_t) content_size;
    }
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (source->content == NULL || ret != SQLITE_DONE) {
        flb_free(source->content);
        source->content = NULL;
        return -1;
    }
    return 0;
}

static int append_source_json(struct azli_candidate_source *source,
                              flb_sds_t *json, size_t included_sources)
{
    flb_sds_t tmp;

    if (source->content == NULL || source->content_size < 2) {
        return -1;
    }
    if (included_sources > 0) {
        tmp = flb_sds_cat(*json, ",", 1);
        if (tmp == NULL) {
            return -1;
        }
        *json = tmp;
    }
    tmp = flb_sds_cat(*json, (const char *) source->content + 1,
                      source->content_size - 2);
    if (tmp == NULL) {
        return -1;
    }
    *json = tmp;
    return 0;
}

static int request_manifest_matches(struct flb_az_li *ctx, const char *name,
                                    const unsigned char digest[AZLI_DIGEST_SIZE],
                                    const unsigned char json_digest[AZLI_DIGEST_SIZE],
                                    size_t source_count)
{
    unsigned char actual_digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    const void *body;
    int body_size;
    int ret;

    if (sqlite3_get_autocommit(ctx->batch->manager->db->handler) == 0) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT r.body_digest,r.body,r.gzip_bytes,r.state,r.json_digest,"
            "(SELECT COUNT(*) FROM azli_sources s WHERE s.request_pk=r.request_pk "
            " AND s.instance_key=r.instance_key),"
            "(SELECT COUNT(*) FROM azli_sources s WHERE s.request_pk=r.request_pk "
            " AND s.instance_key=r.instance_key AND s.state=1) "
            "FROM azli_requests r WHERE r.name=? AND r.instance_key=?",
            -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        body = sqlite3_column_blob(statement, 1);
        body_size = sqlite3_column_bytes(statement, 1);
        ret = body_size >= 0 && sqlite3_column_int64(statement, 2) == body_size &&
              sqlite3_column_bytes(statement, 0) == AZLI_DIGEST_SIZE &&
              hash_bytes(body, (size_t) body_size, actual_digest) == 0 &&
              memcmp(sqlite3_column_blob(statement, 0), digest,
                     AZLI_DIGEST_SIZE) == 0 &&
              memcmp(actual_digest, digest, AZLI_DIGEST_SIZE) == 0 &&
              sqlite3_column_int(statement, 3) == AZLI_REQUEST_READY &&
              sqlite3_column_bytes(statement, 4) == AZLI_DIGEST_SIZE &&
              memcmp(sqlite3_column_blob(statement, 4), json_digest,
                     AZLI_DIGEST_SIZE) == 0 &&
              sqlite3_column_int64(statement, 5) == (int64_t) source_count &&
              sqlite3_column_int64(statement, 6) == (int64_t) source_count ? 1 : -1;
    }
    else if (ret == SQLITE_DONE) {
        ret = 0;
    }
    else {
        ret = -1;
    }
    sqlite3_finalize(statement);
    return ret;
}

static int persist_request(struct flb_az_li *ctx, const void *gzip,
                           size_t gzip_size, const void *json, size_t json_size,
                           struct azli_candidate_source *sources,
                           size_t source_count, size_t record_count)
{
    unsigned char random[8];
    unsigned char body_digest[AZLI_DIGEST_SIZE];
    unsigned char json_digest[AZLI_DIGEST_SIZE];
    uint64_t random_value;
    char name[96];
    sqlite3_stmt *statement;
    int64_t request_pk;
    size_t index;
    size_t reserved_bytes;
    int ret;

    if (source_count == 0 || source_count > AZLI_MAX_REQUEST_SOURCES ||
        flb_random_bytes(random, sizeof(random)) != 0 ||
        hash_bytes(gzip, gzip_size, body_digest) != 0 ||
        hash_bytes(json, json_size, json_digest) != 0 ||
        source_count > (SIZE_MAX - AZLI_REQUEST_DB_RESERVE) /
                       AZLI_MEMBER_DB_RESERVE ||
        gzip_size > SIZE_MAX - AZLI_REQUEST_DB_RESERVE -
                    source_count * AZLI_MEMBER_DB_RESERVE) {
        return -1;
    }
    reserved_bytes = gzip_size + AZLI_REQUEST_DB_RESERVE +
                     source_count * AZLI_MEMBER_DB_RESERVE;
    if (ctx->batch->manager->reserved_bytes < reserved_bytes) {
        return -1;
    }

    memcpy(&random_value, random, sizeof(random_value));
    snprintf(name, sizeof(name), "request-%" PRIx64 "-%" PRIu64 ".gzip",
             random_value, ctx->batch->request_sequence++);
    statement = NULL;
    if (sql_exec(ctx->batch->manager, "BEGIN IMMEDIATE") == -1) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "INSERT INTO azli_requests(instance_key,name,state,json_bytes,gzip_bytes,"
            "body,body_digest,json_digest,bytes,created) VALUES(?,?,?,?,?,?,?,?,?,?)", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 3, AZLI_REQUEST_READY);
    sqlite3_bind_int64(statement, 4, json_size);
    sqlite3_bind_int64(statement, 5, gzip_size);
    sqlite3_bind_blob64(statement, 6, gzip, gzip_size, SQLITE_TRANSIENT);
    sqlite3_bind_blob64(statement, 7, body_digest, AZLI_DIGEST_SIZE,
                        SQLITE_TRANSIENT);
    sqlite3_bind_blob64(statement, 8, json_digest, AZLI_DIGEST_SIZE,
                        SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 9, reserved_bytes);
    sqlite3_bind_int64(statement, 10, now_seconds());
    if (sqlite3_step(statement) != SQLITE_DONE) {
        goto rollback;
    }
    sqlite3_finalize(statement);
    statement = NULL;
    request_pk = sqlite3_last_insert_rowid(ctx->batch->manager->db->handler);

    for (index = 0; index < source_count; index++) {
        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "UPDATE azli_sources SET request_pk=? WHERE source_pk=? "
                "AND instance_key=? AND state=? AND request_pk IS NULL", -1,
                &statement, NULL);
        if (ret != SQLITE_OK) {
            goto rollback;
        }
        sqlite3_bind_int64(statement, 1, request_pk);
        sqlite3_bind_int64(statement, 2, sources[index].source_pk);
        sqlite3_bind_text(statement, 3, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 4, AZLI_SOURCE_READY);
        if (sqlite3_step(statement) != SQLITE_DONE ||
            sqlite3_changes(ctx->batch->manager->db->handler) != 1) {
            goto rollback;
        }
        sqlite3_finalize(statement);
        statement = NULL;
    }
    ret = sql_commit(ctx->batch->manager);
    if (ret != 0) {
        if (ret != 1 ||
            sqlite3_get_autocommit(ctx->batch->manager->db->handler) == 0) {
            return -1;
        }
        ret = request_manifest_matches(ctx, name, body_digest, json_digest,
                                       source_count);
        if (ret != 1) {
            return -1;
        }
        flb_plg_warn(ctx->ins,
                     "request COMMIT returned an error but durable row was reconciled name=%s",
                     name);
    }
    if (manager_recount(ctx->batch->manager) == -1) {
        return -1;
    }
    flb_plg_debug(ctx->ins,
                  "planned durable request chunks=%zu records=%zu json_bytes=%zu gzip_bytes=%zu",
                  source_count, record_count, json_size, gzip_size);
    return 0;

rollback:
    sqlite3_finalize(statement);
    sql_rollback_if_active(ctx->batch->manager);
    return -1;
}

static int request_exists(struct flb_az_li *ctx)
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT 1 FROM azli_requests WHERE instance_key=? "
            "AND state IN (1,2,3,4) LIMIT 1", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        ret = 1;
    }
    else if (ret == SQLITE_DONE) {
        ret = 0;
    }
    else {
        ret = -1;
    }
    sqlite3_finalize(statement);
    return ret;
}

static int reserve_request_locked(struct azli_root_manager *manager,
                                  size_t reserved_bytes)
{
    if (manager_recount(manager) == -1 || reserved_bytes > manager->limit ||
        manager->reserved_bytes > manager->limit - reserved_bytes ||
        manager->logical_used > manager->limit - reserved_bytes -
                                manager->reserved_bytes ||
        manager->physical_used > manager->limit - reserved_bytes -
                                 manager->reserved_bytes) {
        return -1;
    }
    manager->reserved_bytes += reserved_bytes;
    return 0;
}

static void release_request_reservation(struct azli_root_manager *manager,
                                        size_t reserved_bytes)
{
    if (manager->reserved_bytes >= reserved_bytes) {
        manager->reserved_bytes -= reserved_bytes;
    }
    else {
        manager->reserved_bytes = 0;
    }
}

static int plan_request(struct flb_az_li *ctx)
{
    struct azli_root_manager *manager;
    struct azli_candidate_source *sources;
    flb_sds_t json;
    flb_sds_t tmp;
    void *gzip;
    void *candidate_gzip;
    size_t gzip_size;
    size_t candidate_gzip_size;
    size_t candidate_json_size;
    size_t prior_length;
    size_t source_count;
    size_t snapshot_count;
    size_t included_count;
    size_t record_count;
    size_t addition;
    size_t estimated_gzip_size;
    size_t estimated_json_size;
    size_t request_body_bound;
    size_t reserved_bytes;
    size_t index;
    size_t probes;
    int more_sources;
    int uncompressed_boundary;
    int boundary;
    int ret;

    manager = ctx->batch->manager;
    sources = NULL;
    source_count = 0;
    more_sources = FLB_FALSE;
    reserved_bytes = 0;

    pthread_mutex_lock(&manager->mutex);
    ret = request_exists(ctx);
    if (ret != 0) {
        pthread_mutex_unlock(&manager->mutex);
        return ret < 0 ? -1 : 0;
    }
    if (load_candidate_sources(ctx, &sources, &source_count, &more_sources) == -1) {
        pthread_mutex_unlock(&manager->mutex);
        return -1;
    }
    if (source_count == 0) {
        pthread_mutex_unlock(&manager->mutex);
        candidate_sources_destroy(sources, source_count);
        return 0;
    }

    estimated_gzip_size = 0;
    estimated_json_size = 2;
    snapshot_count = 0;
    uncompressed_boundary = FLB_FALSE;
    for (index = 0; index < source_count; index++) {
        addition = (size_t) sources[index].json_bytes - 2;
        if (snapshot_count > 0) {
            if (addition == SIZE_MAX) {
                pthread_mutex_unlock(&manager->mutex);
                candidate_sources_destroy(sources, source_count);
                return -1;
            }
            addition++;
        }
        if (estimated_json_size > ctx->batch_max_uncompressed_size ||
            addition > ctx->batch_max_uncompressed_size - estimated_json_size) {
            uncompressed_boundary = FLB_TRUE;
            more_sources = FLB_TRUE;
            break;
        }
        if ((uint64_t) sources[index].standalone_gzip_bytes >
            SIZE_MAX - estimated_gzip_size) {
            pthread_mutex_unlock(&manager->mutex);
            candidate_sources_destroy(sources, source_count);
            return -1;
        }
        estimated_json_size += addition;
        estimated_gzip_size += (size_t) sources[index].standalone_gzip_bytes;
        snapshot_count++;
    }
    if (snapshot_count == 0) {
        pthread_mutex_unlock(&manager->mutex);
        candidate_sources_destroy(sources, source_count);
        return -1;
    }
    source_count = snapshot_count;
    request_body_bound = estimated_json_size > FLB_AZ_LI_MAX_REQUEST_SIZE - 65536 ?
                         FLB_AZ_LI_MAX_REQUEST_SIZE : estimated_json_size + 65536;
    reserved_bytes = request_body_bound + AZLI_REQUEST_DB_RESERVE +
                     source_count * AZLI_MEMBER_DB_RESERVE;
    if (!more_sources && estimated_gzip_size < ctx->batch_target_size &&
        now_seconds() - sources[0].created < ctx->batch_timeout) {
        pthread_mutex_unlock(&manager->mutex);
        candidate_sources_destroy(sources, source_count);
        return 0;
    }
    if (reserve_request_locked(manager, reserved_bytes) == -1) {
        pthread_mutex_unlock(&manager->mutex);
        candidate_sources_destroy(sources, source_count);
        return -1;
    }
    for (index = 0; index < source_count; index++) {
        ret = load_candidate_content(ctx, &sources[index]);
        if (ret != 0) {
            release_request_reservation(manager, reserved_bytes);
            pthread_mutex_unlock(&manager->mutex);
            candidate_sources_destroy(sources, source_count);
            return ret == -2 ? 0 : -1;
        }
    }
    pthread_mutex_unlock(&manager->mutex);
    flb_plg_debug(ctx->ins,
                  "whole-chunk planner snapshot_bytes=%zu limit=%zu sources=%zu%s",
                  estimated_json_size, ctx->batch_max_uncompressed_size,
                  source_count, uncompressed_boundary ? " boundary" : "");

    json = flb_sds_create("[");
    gzip = NULL;
    gzip_size = 0;
    candidate_json_size = 0;
    included_count = 0;
    record_count = 0;
    probes = 0;
    boundary = FLB_FALSE;
    if (json == NULL) {
        goto error;
    }

    for (index = 0; index < source_count && probes < AZLI_MAX_COMPRESSION_PROBES;
         index++) {
        prior_length = flb_sds_len(json);
        if (append_source_json(&sources[index], &json, included_count) == -1) {
            goto error;
        }
        tmp = flb_sds_cat(json, "]", 1);
        if (tmp == NULL) {
            goto error;
        }
        json = tmp;
        candidate_json_size = flb_sds_len(json);
        if (candidate_json_size > ctx->batch_max_uncompressed_size) {
            flb_sds_len_set(json, prior_length);
            boundary = FLB_TRUE;
            break;
        }
        candidate_gzip = NULL;
        if (flb_gzip_compress(json, candidate_json_size, &candidate_gzip,
                              &candidate_gzip_size) == -1) {
            goto error;
        }
        probes++;
        if (candidate_gzip_size > FLB_AZ_LI_MAX_REQUEST_SIZE) {
            flb_free(candidate_gzip);
            flb_sds_len_set(json, prior_length);
            boundary = FLB_TRUE;
            break;
        }
        flb_free(gzip);
        gzip = candidate_gzip;
        gzip_size = candidate_gzip_size;
        if ((uint64_t) sources[index].record_count > SIZE_MAX - record_count) {
            goto error;
        }
        included_count++;
        record_count += (size_t) sources[index].record_count;
        if (gzip_size >= ctx->batch_target_size) {
            boundary = FLB_TRUE;
            break;
        }
        flb_sds_len_set(json, flb_sds_len(json) - 1);
    }

    if (included_count == 0) {
        goto error;
    }
    if (included_count == AZLI_MAX_REQUEST_SOURCES ||
        probes == AZLI_MAX_COMPRESSION_PROBES) {
        boundary = FLB_TRUE;
    }
    if (!boundary && included_count == source_count && !more_sources &&
        now_seconds() - sources[0].created < ctx->batch_timeout) {
        ret = 0;
        goto done;
    }
    if (json[flb_sds_len(json) - 1] != ']') {
        tmp = flb_sds_cat(json, "]", 1);
        if (tmp == NULL) {
            goto error;
        }
        json = tmp;
    }
    candidate_json_size = flb_sds_len(json);

    pthread_mutex_lock(&manager->mutex);
    ret = persist_request(ctx, gzip, gzip_size, json, candidate_json_size,
                          sources, included_count, record_count);
    release_request_reservation(manager, reserved_bytes);
    metrics_refresh_locked(ctx);
    pthread_mutex_unlock(&manager->mutex);
    if (ret == 0) {
        flb_plg_debug(ctx->ins, "whole-chunk planner probes=%zu limit=%d",
                      probes, AZLI_MAX_COMPRESSION_PROBES);
        ret = 1;
    }
    goto done_unreserved;

error:
    ret = -1;
done:
    pthread_mutex_lock(&manager->mutex);
    release_request_reservation(manager, reserved_bytes);
    metrics_refresh_locked(ctx);
    pthread_mutex_unlock(&manager->mutex);
done_unreserved:
    flb_free(gzip);
    flb_sds_destroy(json);
    candidate_sources_destroy(sources, source_count);
    return ret;
}

static int request_load_next(struct flb_az_li *ctx, struct azli_request *request)
{
    sqlite3_stmt *statement;
    const void *body;
    int body_size;
    int ret;

    memset(request, 0, sizeof(*request));
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT request_pk,name,state,attempts,next_retry,json_bytes,gzip_bytes,"
            "body_digest,json_digest,body FROM azli_requests WHERE instance_key=? "
            "AND state IN (1,2,3) AND next_retry<=? ORDER BY request_pk LIMIT 1",
            -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, now_seconds());
    ret = sqlite3_step(statement);
    if (ret == SQLITE_DONE) {
        sqlite3_finalize(statement);
        return 0;
    }
    if (ret != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return -1;
    }
    body_size = sqlite3_column_bytes(statement, 9);
    if (sqlite3_column_bytes(statement, 7) != AZLI_DIGEST_SIZE ||
        sqlite3_column_bytes(statement, 8) != AZLI_DIGEST_SIZE || body_size < 0) {
        sqlite3_finalize(statement);
        return -1;
    }
    request->request_pk = sqlite3_column_int64(statement, 0);
    request->name = flb_sds_create((const char *) sqlite3_column_text(statement, 1));
    request->state = sqlite3_column_int(statement, 2);
    request->attempts = sqlite3_column_int(statement, 3);
    request->next_retry = sqlite3_column_int64(statement, 4);
    request->json_bytes = sqlite3_column_int64(statement, 5);
    request->gzip_bytes = sqlite3_column_int64(statement, 6);
    memcpy(request->digest, sqlite3_column_blob(statement, 7), AZLI_DIGEST_SIZE);
    memcpy(request->json_digest, sqlite3_column_blob(statement, 8), AZLI_DIGEST_SIZE);
    body = sqlite3_column_blob(statement, 9);
    request->body = flb_malloc((size_t) body_size);
    if (request->body != NULL && body_size > 0) {
        memcpy(request->body, body, (size_t) body_size);
    }
    request->body_size = (size_t) body_size;
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (ret != SQLITE_DONE || request->name == NULL || request->body == NULL) {
        flb_sds_destroy(request->name);
        flb_free(request->body);
        memset(request, 0, sizeof(*request));
        return -1;
    }
    return 1;
}

static int request_mark_inflight(struct flb_az_li *ctx,
                                 struct azli_request *request)
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_requests SET state=?,attempts=attempts+1 WHERE request_pk=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(statement, 1, AZLI_REQUEST_INFLIGHT);
    sqlite3_bind_int64(statement, 2, request->request_pk);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    if (ret == 0 && sqlite3_changes(ctx->batch->manager->db->handler) != 1) {
        ret = -1;
    }
    sqlite3_finalize(statement);
    return ret;
}

static int request_commit_sources(struct flb_az_li *ctx,
                                  struct azli_request *request,
                                  int quarantine, int status,
                                  const char *reason)
{
    unsigned char member_digest[AZLI_DIGEST_SIZE];
    sqlite3_stmt *statement;
    int64_t member_count;
    int64_t member_records;
    int64_t member_bytes;
    int64_t completed;
    int ret;

    statement = NULL;
    if (sql_exec(ctx->batch->manager, "BEGIN IMMEDIATE") == -1) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT COUNT(*),COALESCE(SUM(record_count),0),"
            "COALESCE(SUM(json_bytes),0) FROM azli_sources "
            "WHERE request_pk=? AND instance_key=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_int64(statement, 1, request->request_pk);
    sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        goto rollback;
    }
    member_count = sqlite3_column_int64(statement, 0);
    member_records = sqlite3_column_int64(statement, 1);
    member_bytes = sqlite3_column_int64(statement, 2);
    if (member_count < 1 || member_records < 1 || member_bytes < 2 ||
        sqlite3_step(statement) != SQLITE_DONE) {
        goto rollback;
    }
    sqlite3_finalize(statement);
    statement = NULL;

    if (!quarantine &&
        (validate_request_members(ctx, request->request_pk, member_digest) != 0 ||
         memcmp(member_digest, request->json_digest, AZLI_DIGEST_SIZE) != 0)) {
        goto rollback;
    }
    if (!quarantine) {
        completed = now_seconds();
        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "INSERT INTO azli_receipts(instance_key,source_id,digest,completed,"
                "expires,bytes) SELECT instance_key,source_id,digest,?,?,? "
                "FROM azli_sources WHERE request_pk=? AND instance_key=?", -1,
                &statement, NULL);
        if (ret != SQLITE_OK) {
            goto rollback;
        }
        sqlite3_bind_int64(statement, 1, completed);
        sqlite3_bind_int64(statement, 2,
                           completed + (int64_t) ctx->buffer_receipt_ttl);
        sqlite3_bind_int64(statement, 3, AZLI_RECEIPT_DB_RESERVE);
        sqlite3_bind_int64(statement, 4, request->request_pk);
        sqlite3_bind_text(statement, 5, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) != SQLITE_DONE ||
            sqlite3_changes(ctx->batch->manager->db->handler) != member_count) {
            goto rollback;
        }
        sqlite3_finalize(statement);
        statement = NULL;

        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "UPDATE azli_instances SET last_success=MAX(last_success,?) "
                "WHERE instance_key=?", -1, &statement, NULL);
        if (ret != SQLITE_OK) {
            goto rollback;
        }
        sqlite3_bind_int64(statement, 1, completed);
        sqlite3_bind_text(statement, 2, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) != SQLITE_DONE ||
            sqlite3_changes(ctx->batch->manager->db->handler) != 1) {
            goto rollback;
        }
        sqlite3_finalize(statement);
        statement = NULL;
    }

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_sources SET state=? WHERE request_pk=? AND instance_key=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_int(statement, 1,
                     quarantine ? AZLI_SOURCE_QUARANTINED : AZLI_SOURCE_DRAINED);
    sqlite3_bind_int64(statement, 2, request->request_pk);
    sqlite3_bind_text(statement, 3, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE ||
        sqlite3_changes(ctx->batch->manager->db->handler) != member_count) {
        goto rollback;
    }
    sqlite3_finalize(statement);
    statement = NULL;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_requests SET state=?,status=?,reason=? WHERE request_pk=? "
            "AND instance_key=?", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_int(statement, 1,
                     quarantine ? AZLI_REQUEST_QUARANTINED : AZLI_REQUEST_ACKED);
    sqlite3_bind_int(statement, 2, status);
    if (reason != NULL) {
        sqlite3_bind_text(statement, 3, reason, -1, SQLITE_TRANSIENT);
    }
    else {
        sqlite3_bind_null(statement, 3);
    }
    sqlite3_bind_int64(statement, 4, request->request_pk);
    sqlite3_bind_text(statement, 5, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE ||
        sqlite3_changes(ctx->batch->manager->db->handler) != 1) {
        goto rollback;
    }
    sqlite3_finalize(statement);
    statement = NULL;

    ret = sql_commit(ctx->batch->manager);
    if (ret != 0) {
        if (ret != 1 ||
            sqlite3_get_autocommit(ctx->batch->manager->db->handler) == 0) {
            return -1;
        }
        ret = request_outcome_matches(ctx, request->request_pk, quarantine);
        if (ret != 1) {
            return -1;
        }
        flb_plg_warn(ctx->ins,
                     "request outcome COMMIT returned an error but durable state was "
                     "reconciled name=%s", request->name);
    }
    if (quarantine) {
        metric_counter_add(ctx, ctx->cmt_quarantined_chunks,
                           (double) member_count);
        metric_counter_add(ctx, ctx->cmt_quarantined_records,
                           (double) member_records);
    }
    else {
        metric_counter_add(ctx, ctx->cmt_delivered_chunks,
                           (double) member_count);
        metric_counter_add(ctx, ctx->cmt_delivered_records,
                           (double) member_records);
        metric_counter_add(ctx, ctx->cmt_delivered_bytes,
                           (double) member_bytes);
    }
    if (!quarantine) {
        metric_gauge_set(ctx, ctx->cmt_uploader_last_success,
                         (double) completed);
        if (cleanup_acknowledged(ctx) == -1 ||
            manager_maintain(ctx->batch->manager,
                             ctx->batch->manager->logical_used == 0 ||
                             ctx->batch->manager->wal_bytes >
                             ctx->batch->manager->limit / 4) < 0) {
            return -1;
        }
        metrics_refresh_locked(ctx);
        return 0;
    }
    ret = manager_recount(ctx->batch->manager);
    if (ret == 0) {
        metrics_refresh_locked(ctx);
    }
    return ret;

rollback:
    sqlite3_finalize(statement);
    sql_rollback_if_active(ctx->batch->manager);
    return -1;
}

static time_t retry_delay(struct flb_az_li *ctx, int attempts)
{
    time_t delay;
    int index;

    delay = ctx->upload_retry_base;
    for (index = 1; index < attempts && delay < 60; index++) {
        delay *= 2;
    }
    return delay > 60 ? 60 : delay;
}

static int request_schedule_retry(struct flb_az_li *ctx,
                                  struct azli_request *request, int status)
{
    sqlite3_stmt *statement;
    int ret;

    if (ctx->upload_retry_limit > 0 &&
        request->attempts + 1 > ctx->upload_retry_limit) {
        return request_commit_sources(ctx, request, FLB_TRUE, status,
                                      "retry_exhausted");
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_requests SET state=?,next_retry=?,status=? WHERE request_pk=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(statement, 1, AZLI_REQUEST_RETRY);
    sqlite3_bind_int64(statement, 2,
                       now_seconds() + retry_delay(ctx, request->attempts + 1));
    sqlite3_bind_int(statement, 3, status);
    sqlite3_bind_int64(statement, 4, request->request_pk);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    return ret;
}

static int response_is_transient(int transport_result, int status)
{
    return transport_result != 0 || status == 401 || status == 408 ||
           status == 429 || status >= 500;
}

static void request_destroy(struct azli_request *request)
{
    flb_sds_destroy(request->name);
    flb_free(request->body);
    memset(request, 0, sizeof(*request));
}

static int upload_one(struct flb_az_li *ctx)
{
    struct azli_request request;
    unsigned char body_digest[AZLI_DIGEST_SIZE];
    unsigned char member_digest[AZLI_DIGEST_SIZE];
    int status;
    int ret;
    int transition_ret;

    pthread_mutex_lock(&ctx->batch->manager->mutex);
    ret = request_load_next(ctx, &request);
    if (ret <= 0) {
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        return ret;
    }
    if (request.body_size != (size_t) request.gzip_bytes ||
        hash_bytes(request.body, request.body_size, body_digest) != 0 ||
        memcmp(body_digest, request.digest, AZLI_DIGEST_SIZE) != 0 ||
        request.body_size > FLB_AZ_LI_MAX_REQUEST_SIZE) {
        flb_plg_error(ctx->ins,
                      "durable request BLOB failed validation name=%s", request.name);
        transition_ret = request_commit_sources(ctx, &request, FLB_TRUE, 0,
                                                "artifact_corrupt");
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        request_destroy(&request);
        return transition_ret == 0 ? 1 : -1;
    }
    ret = validate_request_members(ctx, request.request_pk, member_digest);
    if (ret == 0 && memcmp(member_digest, request.json_digest,
                           AZLI_DIGEST_SIZE) != 0) {
        ret = 1;
    }
    if (ret != 0) {
        if (ret > 0) {
            flb_plg_error(ctx->ins,
                          "durable request source member failed validation name=%s",
                          request.name);
            transition_ret = request_commit_sources(ctx, &request, FLB_TRUE, 0,
                                                    "source_corrupt");
        }
        else {
            transition_ret = -1;
        }
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        request_destroy(&request);
        return transition_ret == 0 ? 1 : -1;
    }
    if (request_mark_inflight(ctx, &request) == -1) {
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        request_destroy(&request);
        return -1;
    }
    pthread_mutex_unlock(&ctx->batch->manager->mutex);

    status = 0;
    ret = az_li_send_payload(ctx, request.body, request.body_size,
                             request.json_bytes, FLB_TRUE, &status);
    if (ret == 0 && status == 401) {
        flb_oauth2_invalidate_token(ctx->u_auth);
    }

    pthread_mutex_lock(&ctx->batch->manager->mutex);
    if (ret == 0 && status >= 200 && status <= 299) {
        transition_ret = request_commit_sources(ctx, &request, FLB_FALSE,
                                                status, NULL);
    }
    else if (response_is_transient(ret, status)) {
        transition_ret = request_schedule_retry(ctx, &request, status);
    }
    else {
        transition_ret = request_commit_sources(
                            ctx, &request, FLB_TRUE, status,
                            status == 413 ? "http_413" : "permanent");
    }
    if (transition_ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not persist request outcome name=%s status=%d",
                      request.name, status);
    }
    pthread_mutex_unlock(&ctx->batch->manager->mutex);
    request_destroy(&request);
    return transition_ret == 0 ? 1 : -1;
}

static void batch_timer_return(struct flb_config *config)
{
    struct flb_coro *coro;
    struct flb_sched *scheduler;
    struct flb_sched_timer_coro *timer_coro;

    if (config->hot_reloading == FLB_FALSE && config->is_running == FLB_TRUE) {
        flb_sched_timer_cb_coro_return();
        return;
    }
    coro = flb_coro_get();
    scheduler = flb_sched_ctx_get();
    timer_coro = coro == NULL ? NULL : coro->data;
    if (coro == NULL || scheduler == NULL || timer_coro == NULL) {
        flb_sched_timer_cb_coro_return();
        return;
    }
    cfl_list_del(&timer_coro->_head);
    cfl_list_add(&timer_coro->_head, &scheduler->timer_coro_list_drop);
    flb_coro_yield(coro, FLB_TRUE);
}

static int batch_run_maintenance(struct flb_az_li *ctx, int recovery)
{
    struct azli_root_manager *manager;
    int interval;

    manager = ctx->batch->manager;
    if (recovery) {
        if (sql_rollback_if_active(manager) == -1 ||
            recover_requests(ctx) == -1 || validate_source_rows(ctx) == -1) {
            return -1;
        }
    }
    interval = AZLI_MAINTENANCE_SECONDS;
    if (ctx->buffer_receipt_ttl > 0 && ctx->buffer_receipt_ttl < interval) {
        interval = ctx->buffer_receipt_ttl;
    }
    if (recovery || now_seconds() - manager->last_maintenance >= interval) {
        if (cleanup_expired_receipts(ctx->batch->manager) == -1 ||
            manager_maintain(manager, FLB_FALSE) < 0) {
            return -1;
        }
    }
    return 0;
}

static void batch_timer_callback(struct flb_config *config, void *data)
{
    struct flb_az_li *ctx;
    struct flb_az_li_batch *batch;
    int work_failed;
    int plan_result;
    int upload_result;
    int uploads;
    int index;

    ctx = data;
    batch = ctx->batch;
    if (batch == NULL) {
        batch_timer_return(config);
        return;
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    if (config->is_running == FLB_FALSE || config->hot_reloading == FLB_TRUE ||
        batch->shutting_down || batch->upload_in_progress ||
        (batch->fatal_error && now_seconds() < batch->next_recovery)) {
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        batch_timer_return(config);
        return;
    }
    batch->upload_in_progress = FLB_TRUE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);

    work_failed = FLB_FALSE;
    pthread_mutex_lock(&batch->manager->mutex);
    if (batch_run_maintenance(ctx, batch->fatal_error) == -1) {
        work_failed = FLB_TRUE;
    }
    pthread_mutex_unlock(&batch->manager->mutex);

    uploads = 0;
    for (index = 0; !work_failed && index < AZLI_MAX_UPLOADS_PER_TICK; index++) {
        plan_result = plan_request(ctx);
        if (plan_result < 0) {
            work_failed = FLB_TRUE;
            break;
        }
        upload_result = upload_one(ctx);
        if (upload_result < 0) {
            work_failed = FLB_TRUE;
            break;
        }
        if (upload_result == 0) {
            break;
        }
        uploads++;
    }
    if (uploads > 0) {
        flb_plg_debug(ctx->ins, "batch timer uploads=%d limit=%d",
                      uploads, AZLI_MAX_UPLOADS_PER_TICK);
    }
    if (work_failed) {
        flb_plg_error(ctx->ins,
                      "durable spool work failed; entering recoverable backoff");
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    if (work_failed) {
        batch->fatal_error = FLB_TRUE;
        batch->persistence_degraded = FLB_TRUE;
        batch->consecutive_failures++;
        batch->next_recovery = now_seconds() +
                               retry_delay(ctx, batch->consecutive_failures);
        metric_counter_add(ctx, ctx->cmt_persistence_failures, 1.0);
    }
    else if (batch->fatal_error) {
        flb_plg_info(ctx->ins, "durable spool recovered without restart");
        batch->fatal_error = FLB_FALSE;
        batch->consecutive_failures = 0;
        batch->next_recovery = 0;
        if (batch->persistence_degraded) {
            metric_counter_add(ctx, ctx->cmt_degraded_recoveries, 1.0);
        }
        batch->persistence_degraded = FLB_FALSE;
    }
    batch->upload_in_progress = FLB_FALSE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);
    pthread_mutex_lock(&batch->manager->mutex);
    metrics_refresh_locked(ctx);
    pthread_mutex_unlock(&batch->manager->mutex);
    batch_timer_return(config);
}

int az_li_batch_init(struct flb_az_li *ctx)
{
    struct flb_az_li_batch *batch;
    int ret;

#ifndef _WIN32
    if (mkdir(ctx->buffer_dir, 0700) == -1 && errno != EEXIST) {
        flb_plg_error(ctx->ins, "could not create dedicated buffer_dir path=%s",
                      ctx->buffer_dir);
        return -1;
    }
#endif
    batch = flb_calloc(1, sizeof(*batch));
    if (batch == NULL) {
        return -1;
    }
    pthread_mutex_init(&batch->lifecycle_mutex, NULL);
    batch->lifecycle_initialized = FLB_TRUE;
    ctx->batch = batch;
    batch->manager = manager_acquire(ctx);
    if (batch->manager == NULL) {
        goto error;
    }
    pthread_mutex_lock(&batch->manager->mutex);
    ret = manager_claim_instance(ctx);
    if (ret == 0) {
        ret = instance_attach(ctx);
    }
    if (ret == 0) {
        ret = recover_requests(ctx);
    }
    if (ret == 0) {
        ret = validate_source_rows(ctx);
    }
    if (ret == 0) {
        ret = cleanup_expired_receipts(ctx->batch->manager);
    }
    if (ret == 0) {
        ret = manager_maintain(batch->manager, FLB_TRUE);
    }
    if (ret == 0) {
        metrics_refresh_locked(ctx);
    }
    pthread_mutex_unlock(&batch->manager->mutex);
    if (ret < 0) {
        goto error;
    }

    flb_plg_info(ctx->ins,
                 "SQLite whole-chunk spool enabled path=%s target=%zu "
                 "aggregate_limit=%zu logical=%zu physical=%zu",
                 ctx->buffer_dir, ctx->batch_target_size, batch->manager->limit,
                 batch->manager->logical_used, batch->manager->physical_used);
    return 0;

error:
    if (batch->manager != NULL) {
        pthread_mutex_lock(&batch->manager->mutex);
        manager_release_instance(batch);
        pthread_mutex_unlock(&batch->manager->mutex);
        manager_release(batch->manager);
    }
    if (batch->lifecycle_initialized) {
        pthread_mutex_destroy(&batch->lifecycle_mutex);
    }
    flb_free(batch);
    ctx->batch = NULL;
    return -1;
}

static void uploader_start_retry_callback(struct flb_config *config, void *data)
{
    int shutting_down;
    struct flb_az_li *ctx;
    struct flb_az_li_batch *batch;

    (void) config;
    ctx = data;
    batch = ctx->batch;
    if (batch == NULL) {
        return;
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    batch->uploader_retry_timer = NULL;
    shutting_down = batch->shutting_down;
    pthread_mutex_unlock(&batch->lifecycle_mutex);
    if (shutting_down == FLB_FALSE) {
        az_li_batch_start_uploader(ctx);
    }
}

static void uploader_start_failed(struct flb_az_li *ctx,
                                  struct flb_sched *scheduler)
{
    int schedule_retry;
    struct flb_az_li_batch *batch;

    batch = ctx->batch;
    pthread_mutex_lock(&batch->lifecycle_mutex);
    batch->fatal_error = FLB_TRUE;
    if (batch->consecutive_failures < INT_MAX) {
        batch->consecutive_failures++;
    }
    schedule_retry = batch->uploader_retry_timer == NULL &&
                     batch->shutting_down == FLB_FALSE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);

    metric_gauge_set(ctx, ctx->cmt_uploader_up, 0.0);
    metric_gauge_set(ctx, ctx->cmt_uploader_consecutive_failures,
                     (double) batch->consecutive_failures);
    if (schedule_retry && scheduler != NULL &&
        flb_sched_timer_cb_create(scheduler, FLB_SCHED_TIMER_CB_ONESHOT,
                                  AZLI_TIMER_MS, uploader_start_retry_callback,
                                  ctx, &batch->uploader_retry_timer) == -1) {
        batch->uploader_retry_timer = NULL;
        flb_plg_error(ctx->ins, "could not schedule batching uploader startup retry");
    }
}

int az_li_batch_start_uploader(struct flb_az_li *ctx)
{
    int ret;
    int recovered;
    struct flb_sched *scheduler;
    struct flb_az_li_batch *batch;

    batch = ctx->batch;
    if (batch == NULL) {
        return -1;
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    if (batch->shutting_down == FLB_TRUE) {
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        return -1;
    }
    if (batch->uploader_started == FLB_TRUE) {
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        return 0;
    }
    pthread_mutex_unlock(&batch->lifecycle_mutex);

    scheduler = flb_sched_ctx_get();
    if (scheduler == NULL) {
        uploader_start_failed(ctx, NULL);
        return -1;
    }

    ret = flb_sched_timer_coro_cb_create(scheduler, FLB_SCHED_TIMER_CB_PERM,
                                         AZLI_TIMER_MS, batch_timer_callback,
                                         ctx, NULL);
    if (ret == -1) {
        uploader_start_failed(ctx, scheduler);
        return -1;
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    recovered = batch->fatal_error;
    batch->uploader_started = FLB_TRUE;
    batch->fatal_error = FLB_FALSE;
    batch->consecutive_failures = 0;
    pthread_mutex_unlock(&batch->lifecycle_mutex);
    metric_gauge_set(ctx, ctx->cmt_uploader_up, 1.0);
    metric_gauge_set(ctx, ctx->cmt_uploader_consecutive_failures, 0.0);
    if (recovered) {
        flb_plg_info(ctx->ins, "batching uploader started after retry");
    }
    return 0;
}

void az_li_batch_stop_uploader(struct flb_az_li *ctx)
{
    struct flb_az_li_batch *batch;

    batch = ctx->batch;
    if (batch == NULL) {
        return;
    }
    pthread_mutex_lock(&batch->lifecycle_mutex);
    batch->shutting_down = FLB_TRUE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);
}

void az_li_batch_destroy(struct flb_az_li *ctx)
{
    int upload_in_progress;
    struct flb_az_li_batch *batch;

    batch = ctx->batch;
    if (batch == NULL) {
        return;
    }
    pthread_mutex_lock(&batch->lifecycle_mutex);
    batch->shutting_down = FLB_TRUE;
    upload_in_progress = batch->upload_in_progress;
    pthread_mutex_unlock(&batch->lifecycle_mutex);
    if (upload_in_progress == FLB_TRUE) {
        flb_plg_error(ctx->ins,
                      "refusing to destroy batching state during an active upload");
        return;
    }

    pthread_mutex_lock(&batch->manager->mutex);
    manager_release_instance(batch);
    pthread_mutex_unlock(&batch->manager->mutex);
    manager_release(batch->manager);
    pthread_mutex_destroy(&batch->lifecycle_mutex);
    flb_free(batch);
    ctx->batch = NULL;
}
