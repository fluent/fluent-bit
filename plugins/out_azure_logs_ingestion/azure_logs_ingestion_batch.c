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
#include <fluent-bit/flb_fstore.h>
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
#include <fluent-bit/flb_time.h>
#include <chunkio/cio_chunk.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_batch.h"
#include "azure_logs_ingestion_conf.h"

#define AZLI_SOURCE_STREAM       "sources"
#define AZLI_REQUEST_STREAM      "requests"
#define AZLI_TIMER_MS            1000
#define AZLI_RATIO_ALPHA         0.25
#define AZLI_FILE_OVERHEAD       4096
/* Conservative reservations are charged in addition to actual SQLite files. */
#define AZLI_SOURCE_DB_RESERVE   4096
#define AZLI_REQUEST_DB_RESERVE  4096
#define AZLI_SPAN_DB_RESERVE     256
#define AZLI_MAX_REQUEST_SPANS   256
#define AZLI_MAX_SOURCE_FILES    10000
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

struct azli_root_manager {
    flb_sds_t path;
    size_t limit;
    size_t used;
    size_t files;
    int references;
    int lock_fd;
    struct flb_sqldb *db;
    pthread_mutex_t mutex;
    struct mk_list _head;
};

struct azli_candidate_record {
    int64_t source_pk;
    int64_t record_index;
    size_t json_end;
};

struct azli_source_buffer {
    void *data;
    struct mk_list _head;
};

struct azli_span {
    int64_t source_pk;
    int64_t first_record;
    int64_t record_count;
};

struct azli_request {
    int64_t request_pk;
    int state;
    int attempts;
    int64_t next_retry;
    int64_t json_bytes;
    int64_t gzip_bytes;
    flb_sds_t name;
    unsigned char digest[AZLI_DIGEST_SIZE];
};

static int request_commit_spans(struct flb_az_li *ctx,
                                struct azli_request *request,
                                int quarantine, int status,
                                const char *reason);

struct flb_az_li_batch {
    flb_sds_t root_path;
    struct flb_fstore *fs;
    struct flb_fstore_stream *sources;
    struct flb_fstore_stream *requests;
    struct azli_root_manager *manager;
    pthread_mutex_t lifecycle_mutex;
    int lifecycle_initialized;
    int lock_fd;
    int upload_in_progress;
    int uploader_started;
    int shutting_down;
    int fatal_error;
    uint64_t request_sequence;
    uint64_t probe_count;
    double compression_ratio;
    int compression_ratio_initialized;
};

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

static int lock_spool_root(struct flb_az_li_batch *batch)
{
#ifdef _WIN32
    batch->lock_fd = -1;
    return 0;
#else
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/.owner.lock", batch->root_path);
    batch->lock_fd = open(path, O_CREAT | O_RDWR, 0600);
    if (batch->lock_fd == -1 || flock(batch->lock_fd, LOCK_EX | LOCK_NB) == -1) {
        if (batch->lock_fd != -1) {
            close(batch->lock_fd);
            batch->lock_fd = -1;
        }
        return -1;
    }
    return sync_directory(batch->root_path);
#endif
}

static void unlock_spool_root(struct flb_az_li_batch *batch)
{
#ifndef _WIN32
    if (batch->lock_fd != -1) {
        flock(batch->lock_fd, LOCK_UN);
        close(batch->lock_fd);
        batch->lock_fd = -1;
    }
#else
    (void) batch;
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

static void sql_rollback_if_active(struct azli_root_manager *manager)
{
    if (sqlite3_get_autocommit(manager->db->handler) == 0) {
        sql_exec(manager, "ROLLBACK");
    }
}

static int sql_commit(struct azli_root_manager *manager)
{
    if (sql_exec(manager, "COMMIT") == 0) {
        return 0;
    }

    sql_rollback_if_active(manager);
    return -1;
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

static int digest_from_hex(const char *input,
                           unsigned char digest[AZLI_DIGEST_SIZE])
{
    int index;
    unsigned int value;

    if (input == NULL || strlen(input) != AZLI_HEX_SIZE) {
        return -1;
    }
    for (index = 0; index < AZLI_DIGEST_SIZE; index++) {
        if (sscanf(input + index * 2, "%2x", &value) != 1) {
            return -1;
        }
        digest[index] = (unsigned char) value;
    }
    return 0;
}

static int manager_recount(struct azli_root_manager *manager)
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(manager->db->handler,
            "SELECT COALESCE((SELECT SUM(bytes) FROM azli_sources),0) + "
            "COALESCE((SELECT SUM(bytes) FROM azli_requests),0), "
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
    manager->used = (size_t) sqlite3_column_int64(statement, 0);
    manager->files = (size_t) sqlite3_column_int64(statement, 1);
    sqlite3_finalize(statement);

    if (manager->db->path != NULL) {
        struct stat file_info;
        char path[PATH_MAX];
        const char *suffixes[] = {"", "-wal", "-shm"};
        size_t index;

        for (index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++) {
            snprintf(path, sizeof(path), "%s%s", manager->db->path, suffixes[index]);
            if (stat(path, &file_info) == 0 && file_info.st_size > 0) {
                manager->used += (size_t) file_info.st_size;
            }
        }
    }
    return 0;
}

static int manager_schema(struct azli_root_manager *manager)
{
    const char *schema =
        "PRAGMA journal_mode=WAL;"
        "PRAGMA synchronous=FULL;"
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS azli_settings("
        " root TEXT PRIMARY KEY, disk_limit INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS azli_instances("
        " instance_key TEXT PRIMARY KEY, destination BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS azli_sources("
        " source_pk INTEGER PRIMARY KEY AUTOINCREMENT,"
        " instance_key TEXT NOT NULL, source_id TEXT NOT NULL,"
        " name TEXT NOT NULL, digest BLOB NOT NULL,"
        " record_count INTEGER NOT NULL, next_record INTEGER NOT NULL DEFAULT 0,"
        " bytes INTEGER NOT NULL, created INTEGER NOT NULL, state INTEGER NOT NULL,"
        " has_quarantine INTEGER NOT NULL DEFAULT 0,"
        " UNIQUE(instance_key,source_id));"
        "CREATE INDEX IF NOT EXISTS azli_sources_order "
        " ON azli_sources(instance_key,source_pk);"
        "CREATE TABLE IF NOT EXISTS azli_requests("
        " request_pk INTEGER PRIMARY KEY AUTOINCREMENT,"
        " instance_key TEXT NOT NULL, name TEXT NOT NULL UNIQUE,"
        " state INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,"
        " next_retry INTEGER NOT NULL DEFAULT 0, json_bytes INTEGER NOT NULL,"
        " gzip_bytes INTEGER NOT NULL, body_digest BLOB NOT NULL,"
        " bytes INTEGER NOT NULL, created INTEGER NOT NULL,"
        " status INTEGER NOT NULL DEFAULT 0,"
        " reason TEXT);"
        "CREATE INDEX IF NOT EXISTS azli_requests_order "
        " ON azli_requests(instance_key,request_pk);"
        "CREATE UNIQUE INDEX IF NOT EXISTS azli_one_active_request "
        " ON azli_requests(instance_key) WHERE state IN (1,2,3,4);"
        "CREATE TABLE IF NOT EXISTS azli_spans("
        " request_pk INTEGER NOT NULL REFERENCES azli_requests(request_pk) ON DELETE CASCADE,"
        " ordinal INTEGER NOT NULL, source_pk INTEGER NOT NULL "
        " REFERENCES azli_sources(source_pk),"
        " first_record INTEGER NOT NULL, record_count INTEGER NOT NULL,"
        " PRIMARY KEY(request_pk,ordinal));"
        "CREATE TABLE IF NOT EXISTS azli_receipts("
        " instance_key TEXT NOT NULL, source_id TEXT NOT NULL,"
        " digest BLOB NOT NULL, completed INTEGER NOT NULL,"
        " PRIMARY KEY(instance_key,source_id));";

    return sql_exec(manager, schema);
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
        if (manager->path != NULL) {
            flb_sds_destroy(manager->path);
        }
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
        sqlite3_finalize(statement);
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
        }
    }
    else {
        sqlite3_finalize(statement);
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
    }
    if (manager_recount(manager) == -1) {
        goto error_no_statement;
    }
    mk_list_add(&manager->_head, &manager_registry);
    pthread_mutex_unlock(&manager_registry_mutex);
    return manager;

error:
    sqlite3_finalize(statement);
error_no_statement:
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
        sqlite3_finalize(statement);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "buffer_key belongs to a different destination");
        }
        return ret;
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

static int cleanup_expired_receipts(struct flb_az_li *ctx)
{
    sqlite3_stmt *statement;
    int ret;

    if (ctx->buffer_receipt_ttl == 0) {
        return 0;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "DELETE FROM azli_receipts WHERE instance_key=? AND completed<? "
            "AND NOT EXISTS (SELECT 1 FROM azli_sources s "
            "WHERE s.instance_key=azli_receipts.instance_key "
            "AND s.source_id=azli_receipts.source_id)", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2,
                       now_seconds() - (int64_t) ctx->buffer_receipt_ttl);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    return ret;
}

static int source_content_validate(const void *data, size_t size,
                                   int64_t expected_records)
{
    const char *bytes;
    size_t offset;
    size_t start;
    int64_t records;

    bytes = data;
    start = 0;
    records = 0;
    for (offset = 0; offset < size; offset++) {
        if (bytes[offset] != '\n') {
            continue;
        }
        if (offset == start || bytes[start] != '{' || bytes[offset - 1] != '}') {
            return -1;
        }
        records++;
        start = offset + 1;
    }
    if (start != size || records != expected_records) {
        return -1;
    }
    return 0;
}

static int source_meta_parse(struct flb_fstore_file *file, char source_id[65],
                             unsigned char digest[32], int64_t *record_count,
                             int64_t *created)
{
    char magic[8];
    char digest_text[65];
    long long records;
    long long timestamp;

    if (file->meta_buf == NULL || file->meta_size < 1 ||
        sscanf(file->meta_buf, "%7[^|]|%64[^|]|%64[^|]|%lld|%lld",
               magic, source_id, digest_text, &records, &timestamp) != 5 ||
        strcmp(magic, "AZLIS1") != 0 || digest_from_hex(digest_text, digest) == -1) {
        return -1;
    }
    *record_count = records;
    *created = timestamp;
    return 0;
}

static int recover_sources(struct flb_az_li *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_fstore_file *file;
    sqlite3_stmt *statement;
    unsigned char digest[32];
    unsigned char actual_digest[32];
    char source_id[65];
    int64_t record_count;
    int64_t created;
    ssize_t real_size;
    void *content;
    size_t size;
    int ret;

    mk_list_foreach_safe(head, tmp, &ctx->batch->sources->files) {
        file = mk_list_entry(head, struct flb_fstore_file, _head);
        if (flb_fstore_file_meta_get(ctx->batch->fs, file) == -1 ||
            source_meta_parse(file, source_id, digest, &record_count, &created) == -1) {
            flb_plg_error(ctx->ins, "invalid immutable source metadata file=%s", file->name);
            return -1;
        }
        content = NULL;
        if (flb_fstore_file_content_copy(NULL, file, &content, &size) == -1 ||
            hash_bytes(content, size, actual_digest) != 0 ||
            memcmp(digest, actual_digest, sizeof(digest)) != 0 ||
            source_content_validate(content, size, record_count) == -1) {
            flb_free(content);
            flb_plg_error(ctx->ins, "invalid immutable source content file=%s", file->name);
            return -1;
        }
        flb_free(content);
        real_size = cio_chunk_get_real_size(file->chunk);
        if (real_size < 0) {
            return -1;
        }

        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "SELECT digest FROM azli_sources WHERE instance_key=? AND source_id=?", -1,
                &statement, NULL);
        if (ret != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
        ret = sqlite3_step(statement);
        if (ret == SQLITE_ROW) {
            ret = sqlite3_column_bytes(statement, 0) == 32 &&
                  memcmp(sqlite3_column_blob(statement, 0), digest, 32) == 0 ? 0 : -1;
            sqlite3_finalize(statement);
            if (ret == -1) {
                return -1;
            }
            continue;
        }
        sqlite3_finalize(statement);

        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "SELECT digest FROM azli_receipts WHERE instance_key=? AND source_id=?", -1,
                &statement, NULL);
        if (ret != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
        ret = sqlite3_step(statement);
        if (ret == SQLITE_ROW) {
            ret = sqlite3_column_bytes(statement, 0) == AZLI_DIGEST_SIZE &&
                  memcmp(sqlite3_column_blob(statement, 0), digest,
                         AZLI_DIGEST_SIZE) == 0 ? 0 : -1;
            sqlite3_finalize(statement);
            if (ret == -1) {
                return -1;
            }
            flb_fstore_file_delete(ctx->batch->fs, file);
            if (sync_directory(ctx->batch->sources->path) == -1) {
                return -1;
            }
            continue;
        }
        sqlite3_finalize(statement);

        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "INSERT INTO azli_sources(instance_key,source_id,name,digest,record_count,"
                "next_record,bytes,created,state) VALUES(?,?,?,?,?,0,?,?,?)", -1,
                &statement, NULL);
        if (ret != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, file->name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(statement, 4, digest, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 5, record_count);
        if ((size_t) real_size > SIZE_MAX - AZLI_SOURCE_DB_RESERVE) {
            sqlite3_finalize(statement);
            return -1;
        }
        sqlite3_bind_int64(statement, 6,
                           (size_t) real_size + AZLI_SOURCE_DB_RESERVE);
        sqlite3_bind_int64(statement, 7, created);
        sqlite3_bind_int(statement, 8, AZLI_SOURCE_READY);
        ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(statement);
        if (ret == -1) {
            return -1;
        }
    }
    return 0;
}

static int cleanup_acked_request(struct flb_az_li *ctx, int64_t request_pk,
                                 const char *request_name)
{
    sqlite3_stmt *statement;
    struct flb_fstore_file *file;
    int ret;

    file = flb_fstore_file_get(ctx->batch->fs, ctx->batch->requests,
                               (char *) request_name, strlen(request_name));
    if (file != NULL) {
        flb_fstore_file_delete(ctx->batch->fs, file);
        if (sync_directory(ctx->batch->requests->path) == -1) {
            return -1;
        }
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "DELETE FROM azli_requests WHERE request_pk=? AND state=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, request_pk);
    sqlite3_bind_int(statement, 2, AZLI_REQUEST_ACKED);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    manager_recount(ctx->batch->manager);
    return ret;
}

static int cleanup_drained_sources(struct flb_az_li *ctx)
{
    sqlite3_stmt *query;
    sqlite3_stmt *remove;
    struct flb_fstore_file *file;
    const char *name;
    int64_t source_pk;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT source_pk,name FROM azli_sources WHERE instance_key=? AND state=?", -1,
            &query, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(query, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(query, 2, AZLI_SOURCE_DRAINED);
    while (sqlite3_step(query) == SQLITE_ROW) {
        source_pk = sqlite3_column_int64(query, 0);
        name = (const char *) sqlite3_column_text(query, 1);
        file = flb_fstore_file_get(ctx->batch->fs, ctx->batch->sources,
                                   (char *) name, strlen(name));
        if (file != NULL) {
            flb_fstore_file_delete(ctx->batch->fs, file);
            if (sync_directory(ctx->batch->sources->path) == -1) {
                sqlite3_finalize(query);
                return -1;
            }
        }
        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "DELETE FROM azli_sources WHERE source_pk=?", -1, &remove, NULL);
        if (ret != SQLITE_OK) {
            sqlite3_finalize(query);
            return -1;
        }
        sqlite3_bind_int64(remove, 1, source_pk);
        if (sqlite3_step(remove) != SQLITE_DONE) {
            sqlite3_finalize(remove);
            sqlite3_finalize(query);
            return -1;
        }
        sqlite3_finalize(remove);
    }
    sqlite3_finalize(query);
    manager_recount(ctx->batch->manager);
    return 0;
}

static int recover_requests(struct flb_az_li *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_fstore_file *file;
    sqlite3_stmt *statement;
    const char *name;
    int64_t request_pk;
    int64_t gzip_bytes;
    int state;
    int ret;
    void *body;
    size_t body_size;
    unsigned char digest[AZLI_DIGEST_SIZE];

    /* A request file without a manifest never owned source spans and is safe to remove. */
    mk_list_foreach_safe(head, tmp, &ctx->batch->requests->files) {
        file = mk_list_entry(head, struct flb_fstore_file, _head);
        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "SELECT 1 FROM azli_requests WHERE name=?", -1, &statement, NULL);
        if (ret != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_text(statement, 1, file->name, -1, SQLITE_TRANSIENT);
        ret = sqlite3_step(statement);
        sqlite3_finalize(statement);
        if (ret != SQLITE_ROW) {
            flb_fstore_file_delete(ctx->batch->fs, file);
            if (sync_directory(ctx->batch->requests->path) == -1) {
                return -1;
            }
        }
    }

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT request_pk,name,state,gzip_bytes,body_digest FROM azli_requests "
            "WHERE instance_key=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        request_pk = sqlite3_column_int64(statement, 0);
        name = (const char *) sqlite3_column_text(statement, 1);
        state = sqlite3_column_int(statement, 2);
        gzip_bytes = sqlite3_column_int64(statement, 3);
        if (state == AZLI_REQUEST_ACKED) {
            cleanup_acked_request(ctx, request_pk, name);
            continue;
        }
        if (state == AZLI_REQUEST_QUARANTINED) {
            continue;
        }
        file = flb_fstore_file_get(ctx->batch->fs, ctx->batch->requests,
                                   (char *) name, strlen(name));
        body = NULL;
        if (file == NULL || sqlite3_column_bytes(statement, 4) != AZLI_DIGEST_SIZE ||
            flb_fstore_file_content_copy(NULL, file, &body, &body_size) == -1 ||
            body_size != (size_t) gzip_bytes ||
            hash_bytes(body, body_size, digest) != 0 ||
            memcmp(digest, sqlite3_column_blob(statement, 4),
                   AZLI_DIGEST_SIZE) != 0) {
            struct azli_request corrupt_request;

            flb_free(body);
            memset(&corrupt_request, 0, sizeof(corrupt_request));
            corrupt_request.request_pk = request_pk;
            corrupt_request.name = flb_sds_create(name);
            flb_plg_error(ctx->ins,
                          "request manifest/artifact mismatch name=%s; quarantining spans",
                          name);
            sqlite3_finalize(statement);
            if (corrupt_request.name == NULL ||
                request_commit_spans(ctx, &corrupt_request, FLB_TRUE, 0,
                                     "artifact_corrupt") == -1) {
                flb_sds_destroy(corrupt_request.name);
                return -1;
            }
            flb_sds_destroy(corrupt_request.name);
            return recover_requests(ctx);
        }
        flb_free(body);
    }
    sqlite3_finalize(statement);
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_requests SET state=?,next_retry=? "
            "WHERE instance_key=? AND state=?", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(statement, 1, AZLI_REQUEST_RETRY);
    sqlite3_bind_int64(statement, 2, now_seconds());
    sqlite3_bind_text(statement, 3, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 4, AZLI_REQUEST_INFLIGHT);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    cleanup_drained_sources(ctx);
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

static flb_sds_t records_to_ndjson(flb_sds_t *records, size_t record_count)
{
    flb_sds_t output;
    flb_sds_t tmp;
    size_t size;
    size_t index;

    size = 0;
    for (index = 0; index < record_count; index++) {
        size += flb_sds_len(records[index]) + 1;
    }
    output = flb_sds_create_size(size);
    if (output == NULL) {
        return NULL;
    }
    for (index = 0; index < record_count; index++) {
        tmp = flb_sds_cat(output, records[index], flb_sds_len(records[index]));
        if (tmp == NULL) {
            flb_sds_destroy(output);
            return NULL;
        }
        output = tmp;
        tmp = flb_sds_cat(output, "\n", 1);
        if (tmp == NULL) {
            flb_sds_destroy(output);
            return NULL;
        }
        output = tmp;
    }
    return output;
}

static int receipt_or_source_exists(struct flb_az_li *ctx, const char *source_id,
                                    const unsigned char digest[32])
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT digest FROM azli_sources WHERE instance_key=? AND source_id=? "
            "UNION ALL SELECT digest FROM azli_receipts WHERE instance_key=? AND source_id=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, source_id, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        ret = sqlite3_column_bytes(statement, 0) == 32 &&
              memcmp(sqlite3_column_blob(statement, 0), digest, 32) == 0 ? 1 : -1;
    }
    else {
        ret = 0;
    }
    sqlite3_finalize(statement);
    return ret;
}

int az_li_batch_admit_chunk(struct flb_az_li *ctx,
                            struct flb_output_flush *out_flush,
                            struct flb_event_chunk *event_chunk,
                            flb_sds_t *records, size_t record_count)
{
    char source_id[65];
    char digest_text[65];
    char name[80];
    char metadata[256];
    unsigned char digest[32];
    flb_sds_t ndjson;
    struct flb_fstore_file *file;
    sqlite3_stmt *statement;
    size_t charged_bytes;
    size_t construction_headroom;
    ssize_t real_size;
    int exists;
    int file_created;
    int ret;

    (void) event_chunk;
    pthread_mutex_lock(&ctx->batch->lifecycle_mutex);
    if (ctx->batch->shutting_down || ctx->batch->fatal_error) {
        pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
        return -1;
    }
    pthread_mutex_unlock(&ctx->batch->lifecycle_mutex);
    if (record_count == 0) {
        return 0;
    }
    if (source_identity(ctx, out_flush, source_id) == -1) {
        flb_plg_error(ctx->ins, "cannot resolve durable input chunk identity");
        return -1;
    }
    ndjson = records_to_ndjson(records, record_count);
    if (ndjson == NULL || hash_bytes(ndjson, flb_sds_len(ndjson), digest) != 0) {
        flb_sds_destroy(ndjson);
        return -1;
    }
    digest_hex(digest, digest_text);
    charged_bytes = flb_sds_len(ndjson) + AZLI_FILE_OVERHEAD +
                    AZLI_SOURCE_DB_RESERVE;

    pthread_mutex_lock(&ctx->batch->manager->mutex);
    if (manager_recount(ctx->batch->manager) == -1) {
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        flb_sds_destroy(ndjson);
        return -1;
    }
    exists = receipt_or_source_exists(ctx, source_id, digest);
    if (exists != 0) {
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        flb_sds_destroy(ndjson);
        if (exists < 0) {
            flb_plg_error(ctx->ins, "input chunk identity collision id=%s", source_id);
            return -1;
        }
        flb_plg_debug(ctx->ins, "input chunk already durably owned id=%s", source_id);
        return 0;
    }
    construction_headroom = FLB_AZ_LI_MAX_REQUEST_SIZE +
                            AZLI_FILE_OVERHEAD + AZLI_REQUEST_DB_RESERVE +
                            AZLI_MAX_REQUEST_SPANS * AZLI_SPAN_DB_RESERVE;
    if (ctx->batch->manager->files >= AZLI_MAX_SOURCE_FILES ||
        construction_headroom > ctx->batch->manager->limit ||
        charged_bytes > ctx->batch->manager->limit - construction_headroom ||
        ctx->batch->manager->used >
        ctx->batch->manager->limit - construction_headroom - charged_bytes) {
        flb_plg_error(ctx->ins, "batch buffer full current=%zu incoming=%zu limit=%zu",
                      ctx->batch->manager->used, charged_bytes,
                      ctx->batch->manager->limit);
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        flb_sds_destroy(ndjson);
        return -1;
    }

    snprintf(name, sizeof(name), "%s.source", source_id);
    file_created = FLB_FALSE;
    file = flb_fstore_file_get(ctx->batch->fs, ctx->batch->sources,
                               name, strlen(name));
    if (file == NULL) {
        file_created = FLB_TRUE;
        file = flb_fstore_file_create(ctx->batch->fs, ctx->batch->sources, name, 0);
        if (file == NULL || cio_chunk_tx_begin(file->chunk) != CIO_OK ||
            flb_fstore_file_append(file, ndjson, flb_sds_len(ndjson)) != 0) {
            if (file != NULL) {
                cio_chunk_tx_rollback(file->chunk);
                flb_fstore_file_delete(ctx->batch->fs, file);
            }
            pthread_mutex_unlock(&ctx->batch->manager->mutex);
            flb_sds_destroy(ndjson);
            return -1;
        }
        snprintf(metadata, sizeof(metadata), "AZLIS1|%s|%s|%zu|%" PRId64,
                 source_id, digest_text, record_count, now_seconds());
        if (flb_fstore_file_meta_set(ctx->batch->fs, file, metadata,
                                    strlen(metadata) + 1) == -1 ||
            cio_chunk_tx_commit(file->chunk) != CIO_OK ||
            sync_directory(ctx->batch->sources->path) == -1) {
            cio_chunk_tx_rollback(file->chunk);
            flb_fstore_file_delete(ctx->batch->fs, file);
            pthread_mutex_unlock(&ctx->batch->manager->mutex);
            flb_sds_destroy(ndjson);
            return -1;
        }
    }
    else {
        void *existing_content;
        size_t existing_size;
        unsigned char existing_digest[AZLI_DIGEST_SIZE];

        existing_content = NULL;
        if (flb_fstore_file_content_copy(NULL, file, &existing_content,
                                         &existing_size) == -1 ||
            hash_bytes(existing_content, existing_size, existing_digest) != 0 ||
            existing_size != flb_sds_len(ndjson) ||
            memcmp(existing_digest, digest, AZLI_DIGEST_SIZE) != 0) {
            flb_free(existing_content);
            pthread_mutex_unlock(&ctx->batch->manager->mutex);
            flb_sds_destroy(ndjson);
            return -1;
        }
        flb_free(existing_content);
    }
    real_size = cio_chunk_get_real_size(file->chunk);
    if (real_size < 0 || (size_t) real_size >
        ctx->batch->manager->limit - construction_headroom ||
        (size_t) real_size > SIZE_MAX - AZLI_SOURCE_DB_RESERVE ||
        (size_t) real_size + AZLI_SOURCE_DB_RESERVE >
        ctx->batch->manager->limit - construction_headroom ||
        ctx->batch->manager->used > ctx->batch->manager->limit -
        construction_headroom - ((size_t) real_size + AZLI_SOURCE_DB_RESERVE)) {
        if (file_created) {
            flb_fstore_file_delete(ctx->batch->fs, file);
        }
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        flb_sds_destroy(ndjson);
        return -1;
    }
    if ((size_t) real_size > SIZE_MAX - AZLI_SOURCE_DB_RESERVE) {
        if (file_created) {
            flb_fstore_file_delete(ctx->batch->fs, file);
        }
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        flb_sds_destroy(ndjson);
        return -1;
    }
    charged_bytes = (size_t) real_size + AZLI_SOURCE_DB_RESERVE;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "INSERT INTO azli_sources(instance_key,source_id,name,digest,record_count,"
            "next_record,bytes,created,state) VALUES(?,?,?,?,?,0,?,?,?)", -1,
            &statement, NULL);
    if (ret == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, source_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 3, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(statement, 4, digest, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 5, record_count);
        sqlite3_bind_int64(statement, 6, charged_bytes);
        sqlite3_bind_int64(statement, 7, now_seconds());
        sqlite3_bind_int(statement, 8, AZLI_SOURCE_READY);
        ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(statement);
    }
    if (ret == 0 && manager_recount(ctx->batch->manager) == -1) {
        ret = -1;
    }
    pthread_mutex_unlock(&ctx->batch->manager->mutex);
    flb_plg_debug(ctx->ins,
                  "buffered callback records=%zu probes=0 ratio=%.6f source=%s",
                  record_count,
                  ctx->batch->compression_ratio_initialized ?
                  ctx->batch->compression_ratio : 1.0, source_id);
    flb_sds_destroy(ndjson);
    return ret;
}

static int candidate_add_record(flb_sds_t *json, const char *record,
                                size_t length, size_t count)
{
    flb_sds_t tmp;

    if (count > 0) {
        tmp = flb_sds_cat(*json, ",", 1);
        if (tmp == NULL) {
            return -1;
        }
        *json = tmp;
    }
    tmp = flb_sds_cat(*json, record, length);
    if (tmp == NULL) {
        return -1;
    }
    *json = tmp;
    return 0;
}

static int collect_source_records(struct flb_az_li *ctx, int64_t source_pk,
                                  const char *name, int64_t first_record,
                                  flb_sds_t *json,
                                  struct azli_candidate_record **records,
                                  size_t *count, size_t *capacity,
                                  struct mk_list *buffers)
{
    struct flb_fstore_file *file;
    struct azli_source_buffer *holder;
    struct azli_candidate_record *tmp_records;
    const char *bytes;
    void *data;
    size_t size;
    size_t offset;
    size_t start;
    int64_t index;
    int size_limited;

    file = flb_fstore_file_get(ctx->batch->fs, ctx->batch->sources,
                               (char *) name, strlen(name));
    if (file == NULL || flb_fstore_file_content_copy(NULL, file, &data, &size) == -1) {
        return -1;
    }
    holder = flb_calloc(1, sizeof(*holder));
    if (holder == NULL) {
        flb_free(data);
        return -1;
    }
    holder->data = data;
    mk_list_add(&holder->_head, buffers);
    bytes = data;
    start = 0;
    index = 0;
    size_limited = FLB_FALSE;
    for (offset = 0; offset < size; offset++) {
        if (bytes[offset] != '\n') {
            continue;
        }
        if (index++ < first_record) {
            start = offset + 1;
            continue;
        }
        if (*count > 0 && flb_sds_len(*json) + (offset - start) + 2 >
            ctx->batch_max_uncompressed_size) {
            size_limited = FLB_TRUE;
            break;
        }
        if (*count == *capacity) {
            *capacity = *capacity == 0 ? 256 : *capacity * 2;
            tmp_records = flb_realloc(*records,
                                      *capacity * sizeof(**records));
            if (tmp_records == NULL) {
                return -1;
            }
            *records = tmp_records;
        }
        if (candidate_add_record(json, bytes + start, offset - start, *count) == -1) {
            return -1;
        }
        (*records)[*count].source_pk = source_pk;
        (*records)[*count].record_index = index - 1;
        (*records)[*count].json_end = flb_sds_len(*json);
        (*count)++;
        start = offset + 1;
    }
    return size_limited;
}

static void candidate_buffers_destroy(struct mk_list *buffers)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct azli_source_buffer *holder;

    mk_list_foreach_safe(head, tmp, buffers) {
        holder = mk_list_entry(head, struct azli_source_buffer, _head);
        mk_list_del(&holder->_head);
        flb_free(holder->data);
        flb_free(holder);
    }
}

static int compress_prefix(flb_sds_t json,
                           struct azli_candidate_record *records,
                           size_t count, void **output, size_t *output_size,
                           size_t *json_size)
{
    flb_sds_t candidate;
    flb_sds_t tmp;
    int ret;

    candidate = flb_sds_create_len(json, records[count - 1].json_end);
    if (candidate == NULL) {
        return -1;
    }
    tmp = flb_sds_cat(candidate, "]", 1);
    if (tmp == NULL) {
        flb_sds_destroy(candidate);
        return -1;
    }
    candidate = tmp;
    *json_size = flb_sds_len(candidate);
    ret = flb_gzip_compress(candidate, *json_size, output, output_size);
    flb_sds_destroy(candidate);
    return ret;
}

static int source_mark_singleton_quarantine(struct flb_az_li *ctx,
                                             struct azli_candidate_record *record)
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_sources SET next_record=?,has_quarantine=1,state="
            "CASE WHEN record_count<=? THEN ? ELSE state END WHERE source_pk=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, record->record_index + 1);
    sqlite3_bind_int64(statement, 2, record->record_index + 1);
    sqlite3_bind_int(statement, 3, AZLI_SOURCE_QUARANTINED);
    sqlite3_bind_int64(statement, 4, record->source_pk);
    ret = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(statement);
    return ret;
}

static int request_manifest_matches(struct flb_az_li *ctx, const char *name,
                                    const unsigned char digest[AZLI_DIGEST_SIZE])
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT body_digest FROM azli_requests WHERE name=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, name, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement);
    if (ret == SQLITE_ROW) {
        ret = sqlite3_column_bytes(statement, 0) == AZLI_DIGEST_SIZE &&
              memcmp(sqlite3_column_blob(statement, 0), digest,
                     AZLI_DIGEST_SIZE) == 0 ? 1 : -1;
    }
    else {
        ret = 0;
    }
    sqlite3_finalize(statement);
    return ret;
}

static int persist_request(struct flb_az_li *ctx, const void *gzip,
                           size_t gzip_size, size_t json_size,
                           struct azli_candidate_record *records,
                           size_t record_count)
{
    unsigned char random[8];
    unsigned char body_digest[AZLI_DIGEST_SIZE];
    uint64_t random_value;
    char name[96];
    char digest_text[AZLI_HEX_SIZE + 1];
    char metadata[192];
    struct flb_fstore_file *file;
    struct azli_span *spans;
    sqlite3_stmt *statement;
    int64_t request_pk;
    ssize_t real_size;
    size_t span_count;
    size_t index;
    int ret;
    size_t reserved_bytes;

    if (flb_random_bytes(random, sizeof(random)) != 0 ||
        hash_bytes(gzip, gzip_size, body_digest) != 0) {
        return -1;
    }
    spans = flb_calloc(record_count, sizeof(*spans));
    if (spans == NULL) {
        return -1;
    }
    span_count = 0;
    for (index = 0; index < record_count; index++) {
        if (span_count == 0 ||
            spans[span_count - 1].source_pk != records[index].source_pk ||
            spans[span_count - 1].first_record +
            spans[span_count - 1].record_count != records[index].record_index) {
            spans[span_count].source_pk = records[index].source_pk;
            spans[span_count].first_record = records[index].record_index;
            spans[span_count].record_count = 1;
            span_count++;
        }
        else {
            spans[span_count - 1].record_count++;
        }
    }
    if (span_count > AZLI_MAX_REQUEST_SPANS ||
        span_count > (SIZE_MAX - AZLI_REQUEST_DB_RESERVE) /
                     AZLI_SPAN_DB_RESERVE ||
        gzip_size > SIZE_MAX - AZLI_FILE_OVERHEAD - AZLI_REQUEST_DB_RESERVE -
                    span_count * AZLI_SPAN_DB_RESERVE) {
        flb_free(spans);
        return -1;
    }
    reserved_bytes = gzip_size + AZLI_FILE_OVERHEAD +
                     AZLI_REQUEST_DB_RESERVE +
                     span_count * AZLI_SPAN_DB_RESERVE;
    if (reserved_bytes > ctx->batch->manager->limit ||
        ctx->batch->manager->used >
        ctx->batch->manager->limit - reserved_bytes) {
        flb_free(spans);
        return -1;
    }
    memcpy(&random_value, random, sizeof(random_value));
    digest_hex(body_digest, digest_text);
    snprintf(name, sizeof(name), "request-%" PRIx64 "-%" PRIu64 ".gzip",
             random_value, ctx->batch->request_sequence++);
    snprintf(metadata, sizeof(metadata), "AZLIR1|%s|%zu|%zu",
             digest_text, gzip_size, json_size);
    file = flb_fstore_file_create(ctx->batch->fs, ctx->batch->requests, name, 0);
    if (file == NULL || cio_chunk_tx_begin(file->chunk) != CIO_OK ||
        flb_fstore_file_append(file, (void *) gzip, gzip_size) != 0 ||
        flb_fstore_file_meta_set(ctx->batch->fs, file, metadata,
                                strlen(metadata) + 1) == -1 ||
        cio_chunk_tx_commit(file->chunk) != CIO_OK ||
        sync_directory(ctx->batch->requests->path) == -1) {
        if (file != NULL) {
            cio_chunk_tx_rollback(file->chunk);
            flb_fstore_file_delete(ctx->batch->fs, file);
        }
        flb_free(spans);
        return -1;
    }

    real_size = cio_chunk_get_real_size(file->chunk);
    if (real_size < 0 || (size_t) real_size > SIZE_MAX -
        AZLI_REQUEST_DB_RESERVE - span_count * AZLI_SPAN_DB_RESERVE) {
        flb_fstore_file_delete(ctx->batch->fs, file);
        flb_free(spans);
        return -1;
    }
    reserved_bytes = (size_t) real_size + AZLI_REQUEST_DB_RESERVE +
                     span_count * AZLI_SPAN_DB_RESERVE;
    if (reserved_bytes > ctx->batch->manager->limit ||
        ctx->batch->manager->used >
        ctx->batch->manager->limit - reserved_bytes) {
        flb_fstore_file_delete(ctx->batch->fs, file);
        flb_free(spans);
        return -1;
    }

    if (sql_exec(ctx->batch->manager, "BEGIN IMMEDIATE") == -1) {
        goto error;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "INSERT INTO azli_requests(instance_key,name,state,json_bytes,gzip_bytes,"
            "body_digest,bytes,created) VALUES(?,?,?,?,?,?,?,?)", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 3, AZLI_REQUEST_READY);
    sqlite3_bind_int64(statement, 4, json_size);
    sqlite3_bind_int64(statement, 5, gzip_size);
    sqlite3_bind_blob(statement, 6, body_digest, AZLI_DIGEST_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 7, reserved_bytes);
    sqlite3_bind_int64(statement, 8, now_seconds());
    if (sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        goto rollback;
    }
    sqlite3_finalize(statement);
    request_pk = sqlite3_last_insert_rowid(ctx->batch->manager->db->handler);

    for (index = 0; index < span_count; index++) {
        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "INSERT INTO azli_spans(request_pk,ordinal,source_pk,first_record,record_count)"
                " VALUES(?,?,?,?,?)", -1, &statement, NULL);
        if (ret != SQLITE_OK) {
            goto rollback;
        }
        sqlite3_bind_int64(statement, 1, request_pk);
        sqlite3_bind_int64(statement, 2, index);
        sqlite3_bind_int64(statement, 3, spans[index].source_pk);
        sqlite3_bind_int64(statement, 4, spans[index].first_record);
        sqlite3_bind_int64(statement, 5, spans[index].record_count);
        if (sqlite3_step(statement) != SQLITE_DONE) {
            sqlite3_finalize(statement);
            goto rollback;
        }
        sqlite3_finalize(statement);
    }
    if (sql_commit(ctx->batch->manager) == -1) {
        ret = request_manifest_matches(ctx, name, body_digest);
        if (ret != 1) {
            goto error;
        }
        flb_plg_warn(ctx->ins,
                     "request COMMIT returned an error but durable manifest was reconciled name=%s",
                     name);
    }
    if (manager_recount(ctx->batch->manager) == -1) {
        flb_plg_error(ctx->ins, "could not reconcile shared spool quota after request commit");
    }
    flb_free(spans);
    return 0;

rollback:
    sql_rollback_if_active(ctx->batch->manager);
error:
    flb_fstore_file_delete(ctx->batch->fs, file);
    flb_free(spans);
    return -1;
}

static int request_exists(struct flb_az_li *ctx)
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT 1 FROM azli_requests WHERE instance_key=? AND state IN (1,2,3,4) LIMIT 1",
            -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    ret = sqlite3_step(statement) == SQLITE_ROW ? 1 : 0;
    sqlite3_finalize(statement);
    return ret;
}

static int plan_request(struct flb_az_li *ctx)
{
    struct mk_list buffers;
    struct azli_candidate_record *records;
    sqlite3_stmt *statement;
    flb_sds_t json;
    const char *name;
    int64_t source_pk;
    int64_t next_record;
    int64_t oldest_created;
    size_t capacity;
    size_t count;
    size_t source_count;
    size_t chosen;
    size_t low;
    size_t high;
    size_t middle;
    size_t best;
    size_t gzip_size;
    size_t json_size;
    size_t candidate_gzip_size;
    size_t candidate_json_size;
    uint64_t initial_probe_count;
    void *gzip = NULL;
    void *candidate_gzip;
    int ret;

    ret = request_exists(ctx);
    if (ret != 0) {
        return ret < 0 ? -1 : 0;
    }
    initial_probe_count = ctx->batch->probe_count;
    records = NULL;
    capacity = 0;
    count = 0;
    source_count = 0;
    oldest_created = 0;
    mk_list_init(&buffers);
    json = flb_sds_create("[");
    if (json == NULL) {
        return -1;
    }

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT source_pk,name,next_record,created FROM azli_sources "
            "WHERE instance_key=? AND next_record<record_count AND state IN (1,3) "
            "ORDER BY source_pk", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        goto error;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        source_pk = sqlite3_column_int64(statement, 0);
        name = (const char *) sqlite3_column_text(statement, 1);
        next_record = sqlite3_column_int64(statement, 2);
        if (oldest_created == 0) {
            oldest_created = sqlite3_column_int64(statement, 3);
        }
        if (source_count >= AZLI_MAX_REQUEST_SPANS) {
            break;
        }
        source_count++;
        ret = collect_source_records(ctx, source_pk, name, next_record, &json,
                                     &records, &count, &capacity, &buffers);
        if (ret == -1) {
            sqlite3_finalize(statement);
            goto error;
        }
        if (ret == 1 ||
            flb_sds_len(json) + 2 >= ctx->batch_max_uncompressed_size) {
            break;
        }
    }
    sqlite3_finalize(statement);
    if (count == 0) {
        flb_sds_destroy(json);
        candidate_buffers_destroy(&buffers);
        flb_free(records);
        return 0;
    }

    /* The EWMA only decides when to pay for an exact probe. It never
     * authorizes persistence or transmission of a request. */
    if (ctx->batch->compression_ratio_initialized &&
        (double) (flb_sds_len(json) + 1) * ctx->batch->compression_ratio <
        (double) ctx->batch_target_size &&
        now_seconds() - oldest_created < ctx->batch_timeout &&
        flb_sds_len(json) + 1 < ctx->batch_max_uncompressed_size) {
        flb_plg_debug(ctx->ins,
                      "deferred exact probe using compression ratio=%.6f records=%zu",
                      ctx->batch->compression_ratio, count);
        flb_sds_destroy(json);
        candidate_buffers_destroy(&buffers);
        flb_free(records);
        return 0;
    }

    chosen = count;
    if (ctx->batch->compression_ratio_initialized && count > 1 &&
        (double) (records[count - 1].json_end + 1) *
        ctx->batch->compression_ratio > (double) ctx->batch_target_size) {
        size_t estimated_json_target;

        estimated_json_target = (size_t) ((double) ctx->batch_target_size /
                                          ctx->batch->compression_ratio);
        low = 1;
        high = count;
        best = 0;
        while (low <= high) {
            middle = low + (high - low) / 2;
            if (records[middle - 1].json_end + 1 <= estimated_json_target) {
                best = middle;
                low = middle + 1;
            }
            else {
                high = middle - 1;
            }
        }
        chosen = best < count ? best + 1 : best;
        if (chosen == 0) {
            chosen = 1;
        }
    }
    if (compress_prefix(json, records, chosen, &gzip, &gzip_size, &json_size) == -1) {
        goto error;
    }
    ctx->batch->probe_count++;
    if (json_size > 0) {
        double observed = (double) gzip_size / (double) json_size;
        if (!ctx->batch->compression_ratio_initialized) {
            ctx->batch->compression_ratio = observed;
            ctx->batch->compression_ratio_initialized = FLB_TRUE;
        }
        else {
            ctx->batch->compression_ratio = AZLI_RATIO_ALPHA * observed +
                (1.0 - AZLI_RATIO_ALPHA) * ctx->batch->compression_ratio;
        }
    }

    if (chosen == count && gzip_size < ctx->batch_target_size &&
        now_seconds() - oldest_created < ctx->batch_timeout &&
        json_size < ctx->batch_max_uncompressed_size) {
        flb_free(gzip);
        flb_sds_destroy(json);
        candidate_buffers_destroy(&buffers);
        flb_free(records);
        return 0;
    }

    if (gzip_size > FLB_AZ_LI_MAX_REQUEST_SIZE ||
        json_size > ctx->batch_max_uncompressed_size) {
        flb_free(gzip);
        gzip = NULL;
        low = 1;
        high = count;
        best = 0;
        while (low <= high) {
            middle = low + (high - low) / 2;
            candidate_gzip = NULL;
            if (compress_prefix(json, records, middle, &candidate_gzip,
                                &candidate_gzip_size, &candidate_json_size) == -1) {
                goto error;
            }
            ctx->batch->probe_count++;
            flb_free(candidate_gzip);
            if (candidate_gzip_size <= FLB_AZ_LI_MAX_REQUEST_SIZE &&
                candidate_json_size <= ctx->batch_max_uncompressed_size) {
                best = middle;
                low = middle + 1;
            }
            else {
                if (middle == 1) {
                    high = 0;
                }
                else {
                    high = middle - 1;
                }
            }
        }
        chosen = best;
        if (chosen == 0) {
            chosen = 1;
        }
        if (compress_prefix(json, records, chosen, &gzip, &gzip_size, &json_size) == -1) {
            goto error;
        }
        ctx->batch->probe_count++;
        if (gzip_size > FLB_AZ_LI_MAX_REQUEST_SIZE ||
            json_size > ctx->batch_max_uncompressed_size) {
            flb_free(gzip);
            gzip = NULL;
            if (chosen == 1) {
                ret = source_mark_singleton_quarantine(ctx, &records[0]);
                if (ret == 0) {
                    flb_plg_error(ctx->ins,
                                  "quarantined record compressed_bytes=%zu json_bytes=%zu",
                                  gzip_size, json_size);
                }
                flb_sds_destroy(json);
                candidate_buffers_destroy(&buffers);
                flb_free(records);
                return ret;
            }
            chosen--;
            if (compress_prefix(json, records, chosen, &gzip, &gzip_size,
                                &json_size) == -1) {
                goto error;
            }
            ctx->batch->probe_count++;
        }
    }

    ret = persist_request(ctx, gzip, gzip_size, json_size, records, chosen);
    if (ret == 0) {
        flb_plg_debug(ctx->ins,
                      "planned durable request records=%zu probes=%" PRIu64
                      " ratio=%.6f gzip_bytes=%zu",
                      chosen, ctx->batch->probe_count - initial_probe_count,
                      ctx->batch->compression_ratio, gzip_size);
    }
    flb_free(gzip);
    flb_sds_destroy(json);
    candidate_buffers_destroy(&buffers);
    flb_free(records);
    return ret;

error:
    if (gzip != NULL) {
        flb_free(gzip);
    }
    flb_sds_destroy(json);
    candidate_buffers_destroy(&buffers);
    flb_free(records);
    return -1;
}

static int request_load_next(struct flb_az_li *ctx, struct azli_request *request)
{
    sqlite3_stmt *statement;
    int ret;

    memset(request, 0, sizeof(*request));
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT request_pk,name,state,attempts,next_retry,json_bytes,gzip_bytes,body_digest "
            "FROM azli_requests WHERE instance_key=? AND state IN (1,2,3) "
            "AND next_retry<=? ORDER BY request_pk LIMIT 1", -1, &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, ctx->buffer_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, now_seconds());
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return 0;
    }
    request->request_pk = sqlite3_column_int64(statement, 0);
    request->name = flb_sds_create((const char *) sqlite3_column_text(statement, 1));
    request->state = sqlite3_column_int(statement, 2);
    request->attempts = sqlite3_column_int(statement, 3);
    request->next_retry = sqlite3_column_int64(statement, 4);
    request->json_bytes = sqlite3_column_int64(statement, 5);
    request->gzip_bytes = sqlite3_column_int64(statement, 6);
    if (sqlite3_column_bytes(statement, 7) != AZLI_DIGEST_SIZE) {
        sqlite3_finalize(statement);
        flb_sds_destroy(request->name);
        request->name = NULL;
        return -1;
    }
    memcpy(request->digest, sqlite3_column_blob(statement, 7), AZLI_DIGEST_SIZE);
    sqlite3_finalize(statement);
    return request->name == NULL ? -1 : 1;
}

static int request_mark_inflight(struct flb_az_li *ctx, struct azli_request *request)
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
    sqlite3_finalize(statement);
    return ret;
}

static int request_state_is(struct flb_az_li *ctx, int64_t request_pk,
                            int expected_state)
{
    sqlite3_stmt *statement;
    int ret;

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT state FROM azli_requests WHERE request_pk=?", -1,
            &statement, NULL);
    if (ret != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, request_pk);
    ret = sqlite3_step(statement);
    ret = ret == SQLITE_ROW && sqlite3_column_int(statement, 0) == expected_state;
    sqlite3_finalize(statement);
    return ret;
}

static int request_commit_spans(struct flb_az_li *ctx,
                                struct azli_request *request,
                                int quarantine, int status, const char *reason)
{
    sqlite3_stmt *query;
    sqlite3_stmt *update;
    sqlite3_stmt *receipt;
    int64_t source_pk;
    int64_t end_record;
    int ret;

    if (sql_exec(ctx->batch->manager, "BEGIN IMMEDIATE") == -1) {
        return -1;
    }
    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "SELECT source_pk,first_record+record_count FROM azli_spans "
            "WHERE request_pk=? ORDER BY ordinal", -1, &query, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_int64(query, 1, request->request_pk);
    while (sqlite3_step(query) == SQLITE_ROW) {
        source_pk = sqlite3_column_int64(query, 0);
        end_record = sqlite3_column_int64(query, 1);
        ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                "UPDATE azli_sources SET next_record=MAX(next_record,?),"
                "has_quarantine=MAX(has_quarantine,?),state="
                "CASE WHEN record_count<=? THEN CASE WHEN has_quarantine=1 OR ?=1 "
                "THEN ? ELSE ? END ELSE state END WHERE source_pk=?", -1,
                &update, NULL);
        if (ret != SQLITE_OK) {
            sqlite3_finalize(query);
            goto rollback;
        }
        sqlite3_bind_int64(update, 1, end_record);
        sqlite3_bind_int(update, 2, quarantine);
        sqlite3_bind_int64(update, 3, end_record);
        sqlite3_bind_int(update, 4, quarantine);
        sqlite3_bind_int(update, 5, AZLI_SOURCE_QUARANTINED);
        sqlite3_bind_int(update, 6, AZLI_SOURCE_DRAINED);
        sqlite3_bind_int64(update, 7, source_pk);
        if (sqlite3_step(update) != SQLITE_DONE) {
            sqlite3_finalize(update);
            sqlite3_finalize(query);
            goto rollback;
        }
        sqlite3_finalize(update);

        if (!quarantine) {
            ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
                    "INSERT OR IGNORE INTO azli_receipts(instance_key,source_id,digest,completed) "
                    "SELECT instance_key,source_id,digest,? FROM azli_sources "
                    "WHERE source_pk=? AND next_record>=record_count AND has_quarantine=0", -1,
                    &receipt, NULL);
            if (ret != SQLITE_OK) {
                sqlite3_finalize(query);
                goto rollback;
            }
            sqlite3_bind_int64(receipt, 1, now_seconds());
            sqlite3_bind_int64(receipt, 2, source_pk);
            sqlite3_step(receipt);
            sqlite3_finalize(receipt);
        }
    }
    sqlite3_finalize(query);

    ret = sqlite3_prepare_v2(ctx->batch->manager->db->handler,
            "UPDATE azli_requests SET state=?,status=?,reason=? WHERE request_pk=?", -1,
            &update, NULL);
    if (ret != SQLITE_OK) {
        goto rollback;
    }
    sqlite3_bind_int(update, 1, quarantine ? AZLI_REQUEST_QUARANTINED : AZLI_REQUEST_ACKED);
    sqlite3_bind_int(update, 2, status);
    if (reason != NULL) {
        sqlite3_bind_text(update, 3, reason, -1, SQLITE_TRANSIENT);
    }
    else {
        sqlite3_bind_null(update, 3);
    }
    sqlite3_bind_int64(update, 4, request->request_pk);
    if (sqlite3_step(update) != SQLITE_DONE) {
        sqlite3_finalize(update);
        goto rollback;
    }
    sqlite3_finalize(update);
    if (sql_commit(ctx->batch->manager) == -1) {
        ret = request_state_is(ctx, request->request_pk,
                               quarantine ? AZLI_REQUEST_QUARANTINED :
                               AZLI_REQUEST_ACKED);
        if (ret != 1) {
            return -1;
        }
        flb_plg_warn(ctx->ins,
                     "request outcome COMMIT returned an error but durable state was reconciled name=%s",
                     request->name);
    }
    if (!quarantine &&
        (cleanup_acked_request(ctx, request->request_pk, request->name) == -1 ||
         cleanup_drained_sources(ctx) == -1)) {
        return -1;
    }
    if (manager_recount(ctx->batch->manager) == -1) {
        return -1;
    }
    return 0;

rollback:
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
        return request_commit_spans(ctx, request, FLB_TRUE, status,
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

static int upload_one(struct flb_az_li *ctx)
{
    struct azli_request request;
    struct flb_fstore_file *file;
    void *body;
    size_t body_size;
    unsigned char body_digest[AZLI_DIGEST_SIZE];
    int status;
    int ret;
    int transition_ret;

    body = NULL;
    body_size = 0;
    pthread_mutex_lock(&ctx->batch->manager->mutex);
    ret = request_load_next(ctx, &request);
    if (ret <= 0) {
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        return ret;
    }
    file = flb_fstore_file_get(ctx->batch->fs, ctx->batch->requests,
                               request.name, flb_sds_len(request.name));
    if (file == NULL ||
        flb_fstore_file_content_copy(NULL, file, &body, &body_size) == -1 ||
        body_size != (size_t) request.gzip_bytes ||
        hash_bytes(body, body_size, body_digest) != 0 ||
        memcmp(body_digest, request.digest, AZLI_DIGEST_SIZE) != 0 ||
        body_size > FLB_AZ_LI_MAX_REQUEST_SIZE ||
        request.json_bytes > (int64_t) ctx->batch_max_uncompressed_size) {
        flb_plg_error(ctx->ins,
                      "durable request artifact failed validation name=%s",
                      request.name);
        flb_free(body);
        transition_ret = request_commit_spans(ctx, &request, FLB_TRUE, 0,
                                              "artifact_corrupt");
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        flb_sds_destroy(request.name);
        return transition_ret;
    }
    if (request_mark_inflight(ctx, &request) == -1) {
        flb_plg_error(ctx->ins,
                      "could not persist inflight request state name=%s",
                      request.name);
        flb_free(body);
        pthread_mutex_unlock(&ctx->batch->manager->mutex);
        flb_sds_destroy(request.name);
        return -1;
    }
    pthread_mutex_unlock(&ctx->batch->manager->mutex);

    status = 0;
    ret = az_li_send_payload(ctx, body, body_size, request.json_bytes,
                             FLB_TRUE, &status);
    flb_free(body);
    if (ret == 0 && status == 401) {
        flb_oauth2_invalidate_token(ctx->u_auth);
    }

    pthread_mutex_lock(&ctx->batch->manager->mutex);
    if (ret == 0 && status >= 200 && status <= 299) {
        transition_ret = request_commit_spans(ctx, &request, FLB_FALSE,
                                              status, NULL);
    }
    else if (response_is_transient(ret, status)) {
        transition_ret = request_schedule_retry(ctx, &request, status);
    }
    else {
        transition_ret = request_commit_spans(
                            ctx, &request, FLB_TRUE, status,
                            status == 413 ? "http_413" : "permanent");
    }
    if (transition_ret == -1) {
        flb_plg_error(ctx->ins,
                      "could not persist request outcome name=%s status=%d",
                      request.name, status);
    }
    pthread_mutex_unlock(&ctx->batch->manager->mutex);
    flb_sds_destroy(request.name);
    return transition_ret;
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

    /* The output worker exits as soon as its last upstream becomes idle. A
     * timer coroutine completing during shutdown must therefore publish
     * itself directly to the drop list instead of relying on a later pipe
     * event that the worker might never process. The worker loop performs its
     * normal scheduler drop-list cleanup before checking whether it can exit. */
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

static void batch_timer_callback(struct flb_config *config, void *data)
{
    struct flb_az_li *ctx;
    struct flb_az_li_batch *batch;

    ctx = data;
    batch = ctx->batch;
    if (batch == NULL) {
        batch_timer_return(config);
        return;
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    if (config->is_running == FLB_FALSE || config->hot_reloading == FLB_TRUE ||
        batch->shutting_down || batch->upload_in_progress || batch->fatal_error) {
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        batch_timer_return(config);
        return;
    }
    batch->upload_in_progress = FLB_TRUE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);

    pthread_mutex_lock(&batch->manager->mutex);
    if (plan_request(ctx) == -1) {
        flb_plg_error(ctx->ins, "could not plan durable buffered request");
    }
    pthread_mutex_unlock(&batch->manager->mutex);
    if (upload_one(ctx) == -1) {
        pthread_mutex_lock(&batch->lifecycle_mutex);
        batch->fatal_error = FLB_TRUE;
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        flb_plg_error(ctx->ins,
                      "durable uploader stopped after a state persistence failure");
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    batch->upload_in_progress = FLB_FALSE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);
    batch_timer_return(config);
}

int az_li_batch_init(struct flb_az_li *ctx)
{
    flb_sds_t root;
    struct flb_az_li_batch *batch;
    int ret;

    batch = flb_calloc(1, sizeof(*batch));
    if (batch == NULL) {
        return -1;
    }
    batch->lock_fd = -1;
    pthread_mutex_init(&batch->lifecycle_mutex, NULL);
    batch->lifecycle_initialized = FLB_TRUE;
    root = flb_sds_create_size(strlen(ctx->buffer_dir) + strlen(ctx->buffer_key) + 2);
    if (root == NULL) {
        goto error;
    }
    root = flb_sds_printf(&root, "%s/%s", ctx->buffer_dir, ctx->buffer_key);
    if (root == NULL) {
        goto error;
    }
    batch->root_path = root;
    batch->fs = flb_fstore_create(root, FLB_FSTORE_FS);
    if (batch->fs == NULL) {
        goto error;
    }
    if (lock_spool_root(batch) == -1) {
        flb_plg_error(ctx->ins, "buffer_key is already owned by another process");
        goto error;
    }
    batch->sources = flb_fstore_stream_create(batch->fs, AZLI_SOURCE_STREAM);
    batch->requests = flb_fstore_stream_create(batch->fs, AZLI_REQUEST_STREAM);
    if (batch->sources == NULL || batch->requests == NULL) {
        goto error;
    }
    ctx->batch = batch;
    batch->manager = manager_acquire(ctx);
    if (batch->manager == NULL) {
        goto error;
    }
    pthread_mutex_lock(&batch->manager->mutex);
    ret = instance_attach(ctx);
    if (ret == 0) {
        ret = recover_sources(ctx);
    }
    if (ret == 0) {
        ret = recover_requests(ctx);
    }
    if (ret == 0) {
        ret = cleanup_expired_receipts(ctx);
    }
    if (ret == 0) {
        ret = manager_recount(batch->manager);
    }
    pthread_mutex_unlock(&batch->manager->mutex);
    if (ret == -1) {
        goto error;
    }

    flb_plg_info(ctx->ins,
                 "chunk spool enabled path=%s target=%zu aggregate_limit=%zu used=%zu",
                 root, ctx->batch_target_size, batch->manager->limit,
                 batch->manager->used);
    return 0;

error:
    if (batch->manager != NULL) {
        manager_release(batch->manager);
    }
    unlock_spool_root(batch);
    if (batch->fs != NULL) {
        flb_fstore_destroy(batch->fs);
    }
    if (batch->root_path != NULL) {
        flb_sds_destroy(batch->root_path);
    }
    if (batch->lifecycle_initialized) {
        pthread_mutex_destroy(&batch->lifecycle_mutex);
    }
    flb_free(batch);
    ctx->batch = NULL;
    return -1;
}

int az_li_batch_start_uploader(struct flb_az_li *ctx)
{
    int ret;
    struct flb_sched *scheduler;
    struct flb_az_li_batch *batch;

    batch = ctx->batch;
    if (batch == NULL) {
        return -1;
    }

    pthread_mutex_lock(&batch->lifecycle_mutex);
    if (batch->uploader_started == FLB_TRUE) {
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        return 0;
    }
    pthread_mutex_unlock(&batch->lifecycle_mutex);

    scheduler = flb_sched_ctx_get();
    if (scheduler == NULL) {
        pthread_mutex_lock(&batch->lifecycle_mutex);
        batch->fatal_error = FLB_TRUE;
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        return -1;
    }

    ret = flb_sched_timer_coro_cb_create(scheduler, FLB_SCHED_TIMER_CB_PERM,
                                         AZLI_TIMER_MS, batch_timer_callback,
                                         ctx, NULL);
    pthread_mutex_lock(&batch->lifecycle_mutex);
    if (ret == -1) {
        batch->fatal_error = FLB_TRUE;
        pthread_mutex_unlock(&batch->lifecycle_mutex);
        return -1;
    }
    batch->uploader_started = FLB_TRUE;
    batch->fatal_error = FLB_FALSE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);
    return 0;
}

void az_li_batch_destroy(struct flb_az_li *ctx)
{
    struct flb_az_li_batch *batch;

    batch = ctx->batch;
    if (batch == NULL) {
        return;
    }

    /* Buffered mode uses exactly one Fluent Bit output worker. The worker
     * event loop drains an active upstream request before cb_worker_exit runs,
     * and the worker pool is joined before this output exit callback. It is
     * therefore safe to release the spool synchronously for the replacement
     * hot-reload generation. */
    pthread_mutex_lock(&batch->lifecycle_mutex);
    batch->shutting_down = FLB_TRUE;
    pthread_mutex_unlock(&batch->lifecycle_mutex);

    manager_release(batch->manager);
    unlock_spool_root(batch);
    flb_fstore_destroy(batch->fs);
    flb_sds_destroy(batch->root_path);
    pthread_mutex_destroy(&batch->lifecycle_mutex);
    flb_free(batch);
    ctx->batch = NULL;
}
