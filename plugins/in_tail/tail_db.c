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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sqldb.h>

#include "tail_db.h"
#include "tail_sql.h"
#include "tail_file.h"

#include <errno.h>
#include <inttypes.h>
#include <string.h>

struct query_status {
    int id;
    int rows;
    int64_t offset;
};

struct stale_file {
    uint64_t id;
    struct mk_list _head;
};

static int db_apply_migration_if_needed(struct flb_tail_config *ctx,
                                        struct flb_sqldb *db,
                                        const char *sql)
{
    int ret;
    char *err = NULL;

    ret = sqlite3_exec(db->handler, sql, NULL, NULL, &err);
    if (ret != SQLITE_OK) {
        if (err != NULL &&
            (strstr(err, "duplicate column name") != NULL ||
             strstr(err, "already exists") != NULL)) {
            sqlite3_free(err);
            return FLB_OK;
        }

        flb_plg_error(ctx->ins, "db migration failed: %s", err ? err : "unknown error");
        if (err != NULL) {
            sqlite3_free(err);
        }
        return FLB_ERROR;
    }

    return FLB_OK;
}

static inline int tail_db_lock(struct flb_tail_config *ctx)
{
    if (ctx->db == NULL) {
        return 0;
    }

    return flb_sqldb_lock(ctx->db);
}

static inline int tail_db_unlock(struct flb_tail_config *ctx)
{
    if (ctx->db == NULL) {
        return 0;
    }

    return flb_sqldb_unlock(ctx->db);
}

/* Open or create database required by tail plugin */
struct flb_sqldb *flb_tail_db_open(const char *path,
                                   struct flb_input_instance *in,
                                   struct flb_tail_config *ctx,
                                   struct flb_config *config)
{
    int ret;
    char tmp[64];
    struct flb_sqldb *db;

    /* Open/create the database */
    db = flb_sqldb_open(path, in->name, config);
    if (!db) {
        return NULL;
    }

    /* Create table schema if it don't exists */
    ret = flb_sqldb_query(db, SQL_CREATE_FILES, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: could not create 'in_tail_files' table");
        flb_sqldb_close(db);
        return NULL;
    }

    if (ctx->db_sync >= 0) {
        snprintf(tmp, sizeof(tmp) - 1, SQL_PRAGMA_SYNC,
                 ctx->db_sync);
        ret = flb_sqldb_query(db, tmp, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db could not set pragma 'sync'");
            flb_sqldb_close(db);
            return NULL;
        }
    }

    if (ctx->db_locking == FLB_TRUE) {
        ret = flb_sqldb_query(db, SQL_PRAGMA_LOCKING_MODE, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db: could not set pragma 'locking_mode'");
            flb_sqldb_close(db);
            return NULL;
        }
    }

    if (ctx->db_journal_mode) {
        snprintf(tmp, sizeof(tmp) - 1, SQL_PRAGMA_JOURNAL_MODE,
                 ctx->db_journal_mode);
        ret = flb_sqldb_query(db, tmp, NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db could not set pragma 'journal_mode'");
            flb_sqldb_close(db);
            return NULL;
        }
    }

    ret = db_apply_migration_if_needed(ctx, db,
                                       SQL_ALTER_FILES_ADD_OFFSET_MARKER);
    if (ret != FLB_OK) {
        flb_sqldb_close(db);
        return NULL;
    }

    ret = db_apply_migration_if_needed(ctx, db,
                                       SQL_ALTER_FILES_ADD_OFFSET_MARKER_SIZE);
    if (ret != FLB_OK) {
        flb_sqldb_close(db);
        return NULL;
    }

    return db;
}

int flb_tail_db_close(struct flb_sqldb *db)
{
    flb_sqldb_close(db);
    return 0;
}

static int flb_tail_db_file_delete_by_id(struct flb_tail_config *ctx,
                                         uint64_t id)
{
    int ret;

    /* Bind parameters */
    ret = sqlite3_bind_int64(ctx->stmt_delete_file, 1, id);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "db: error binding id=%"PRIu64", ret=%d", id, ret);
        return -1;
    }

    ret = sqlite3_step(ctx->stmt_delete_file);

    sqlite3_clear_bindings(ctx->stmt_delete_file);
    sqlite3_reset(ctx->stmt_delete_file);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error deleting stale entry from database:"
                      " id=%"PRIu64, id);
        return -1;
    }

    flb_plg_info(ctx->ins, "db: stale file deleted from database:"
                 " id=%"PRIu64, id);
    return 0;
}

static int stale_file_matches(struct flb_tail_config *ctx,
                              flb_tail_db_inode_check_fn inode_is_monitored,
                              void *data,
                              const char *path, uint64_t inode)
{
    int ret;
    struct stat st;

#ifdef FLB_SYSTEM_WINDOWS
    if (ctx->windows_path_encoding == FLB_TAIL_WINDOWS_PATH_ENCODING_UTF8) {
        ret = win32_stat_utf8(path, &st);
    }
    else {
        ret = stat(path, &st);
    }
#else
    ret = stat(path, &st);
#endif

    if (ret == 0 && inode == (uint64_t) st.st_ino) {
        return FLB_TRUE;
    }

    if (inode_is_monitored != NULL &&
        inode_is_monitored(inode, data) == FLB_TRUE) {
        return FLB_TRUE;
    }

    if (ret == 0) {
        return FLB_FALSE;
    }

    if (errno == ENOENT || errno == ENOTDIR) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int stale_file_delete_missing(struct flb_tail_config *ctx,
                                     flb_tail_db_inode_check_fn inode_is_monitored,
                                     void *data,
                                     sqlite3_stmt *stmt, int *deleted_count)
{
    int ret;
    int result = 0;
    const char *name;
    struct mk_list stale_files;
    struct mk_list *head;
    struct mk_list *tmp;
    struct stale_file *stale_file;

    mk_list_init(&stale_files);
    *deleted_count = 0;

    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
        name = (const char *) sqlite3_column_text(stmt, 1);
        if (name == NULL ||
            stale_file_matches(ctx, inode_is_monitored, data, name,
                               sqlite3_column_int64(stmt, 2)) == FLB_TRUE) {
            continue;
        }

        stale_file = flb_malloc(sizeof(struct stale_file));
        if (stale_file == NULL) {
            flb_errno();
            result = -1;
            goto cleanup;
        }

        stale_file->id = sqlite3_column_int64(stmt, 0);
        mk_list_add(&stale_file->_head, &stale_files);
    }

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: cannot query stale files: ret=%d", ret);
        result = -1;
        goto cleanup;
    }

    mk_list_foreach(head, &stale_files) {
        stale_file = mk_list_entry(head, struct stale_file, _head);
        ret = flb_tail_db_file_delete_by_id(ctx, stale_file->id);
        if (ret != 0) {
            result = -1;
            goto cleanup;
        }
        (*deleted_count)++;
    }

cleanup:
    mk_list_foreach_safe(head, tmp, &stale_files) {
        stale_file = mk_list_entry(head, struct stale_file, _head);
        mk_list_del(&stale_file->_head);
        flb_free(stale_file);
    }

    return result;
}

/*
 * Check if an file inode exists in the database.
 * If the 'compare_filename' option is enabled,
 * it checks along with the filename. Return FLB_TRUE or FLB_FALSE
 */
static int db_file_exists(struct flb_tail_file *file,
                          struct flb_tail_config *ctx,
                          uint64_t *id, uint64_t *inode, off_t *offset,
                          uint64_t *offset_marker, size_t *offset_marker_size)
{
    int ret;
    int exists = FLB_FALSE;
    const unsigned char *name;

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_get_file, 1, file->inode);
    ret = sqlite3_step(ctx->stmt_get_file);

    if (ret == SQLITE_ROW) {
        exists = FLB_TRUE;

        /* id: column 0 */
        *id = sqlite3_column_int64(ctx->stmt_get_file, 0);

        /* name: column 1 */
        name = sqlite3_column_text(ctx->stmt_get_file, 1);
        if (ctx->compare_filename && name == NULL) {
            flb_plg_error(ctx->ins, "db: error getting name: id=%"PRIu64, *id);
            return -1;
        }

        /* offset: column 2 */
        *offset = sqlite3_column_int64(ctx->stmt_get_file, 2);

        /* inode: column 3 */
        *inode = sqlite3_column_int64(ctx->stmt_get_file, 3);

        /* offset_marker: column 4 */
        *offset_marker = sqlite3_column_int64(ctx->stmt_get_file, 4);

        /* offset_marker_size: column 5 */
        *offset_marker_size = sqlite3_column_int64(ctx->stmt_get_file, 5);

        /* Checking if the file's name and inode match exactly */
        if (ctx->compare_filename) {
            if (flb_tail_target_file_name_cmp((char *) name, file) != 0) {
                exists = FLB_FALSE;
                flb_plg_debug(ctx->ins, "db: exists stale file from database:"
                             " id=%"PRIu64" inode=%"PRIu64" offset=%"PRIu64
                             " name=%s file_inode=%"PRIu64" file_name=%s",
                             *id, *inode, *offset, name, file->inode,
                             file->name);
            }
        }
    }
    else if (ret == SQLITE_DONE) {
        /* all good */
    }
    else {
        exists = -1;
    }

    sqlite3_clear_bindings(ctx->stmt_get_file);
    sqlite3_reset(ctx->stmt_get_file);

    return exists;

}

static int db_file_insert(struct flb_tail_file *file, struct flb_tail_config *ctx)

{
    int ret;
    time_t created;
    off_t db_offset;

    /* Register the file */
    created = time(NULL);
    db_offset = flb_tail_file_db_offset(file);

    ret = flb_tail_file_update_offset_marker(file);
    if (ret < 0) {
        flb_plg_error(ctx->ins,
                      "db: cannot compute offset marker for insert %s inode=%" PRIu64,
                      file->name, file->inode);
        return -1;
    }

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_insert_file, 1, file->name, -1, 0);
    sqlite3_bind_int64(ctx->stmt_insert_file, 2, db_offset);
    sqlite3_bind_int64(ctx->stmt_insert_file, 3, file->inode);
    sqlite3_bind_int64(ctx->stmt_insert_file, 4, created);
    sqlite3_bind_int64(ctx->stmt_insert_file, 5, file->db_offset_marker);
    sqlite3_bind_int64(ctx->stmt_insert_file, 6, file->db_offset_marker_size);

    /* Run the insert */
    ret = sqlite3_step(ctx->stmt_insert_file);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_insert_file);
        sqlite3_reset(ctx->stmt_insert_file);
        flb_plg_error(ctx->ins, "cannot execute insert file %s inode=%" PRIu64,
                      file->name, file->inode);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_insert_file);
    sqlite3_reset(ctx->stmt_insert_file);

    /* Get the database ID for this file */
    return flb_sqldb_last_id(ctx->db);
}

int flb_tail_db_file_set(struct flb_tail_file *file,
                         struct flb_tail_config *ctx)
{
    int ret;
    uint64_t id = 0;
    off_t offset = 0;
    uint64_t inode = 0;
    uint64_t offset_marker = 0;
    size_t offset_marker_size = 0;

    flb_plg_debug(ctx->ins, "db file set called for %s inode=%"PRIu64,
                  file->name, file->inode);

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    /* Check if the file exists */
    ret = db_file_exists(file, ctx, &id, &inode, &offset,
                         &offset_marker, &offset_marker_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot execute query to check inode: %" PRIu64,
                      file->inode);
        tail_db_unlock(ctx);
        return -1;
    }

    if (ret == FLB_FALSE) {
        /* Delete stale file of same inode */
        if (ctx->compare_filename && id > 0) {
            flb_tail_db_file_delete_by_id(ctx, id);
        }

        /* Get the database ID for this file */
        file->db_id = db_file_insert(file, ctx);
    }
    else {
        file->db_id = id;
        file->offset = offset;
        file->db_offset_marker = offset_marker;
        file->db_offset_marker_size = offset_marker_size;
    }

    tail_db_unlock(ctx);
    return 0;
}

/* Update Offset v2 */
int flb_tail_db_file_offset(struct flb_tail_file *file,
                            struct flb_tail_config *ctx)
{
    int ret;
    off_t db_offset;

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    db_offset = flb_tail_file_db_offset(file);
    ret = flb_tail_file_update_offset_marker(file);
    if (ret < 0) {
        flb_plg_error(ctx->ins,
                      "db: cannot compute offset marker for update %s inode=%" PRIu64,
                      file->name, file->inode);
        tail_db_unlock(ctx);
        return -1;
    }

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_offset, 1, db_offset);
    sqlite3_bind_int64(ctx->stmt_offset, 2, file->db_offset_marker);
    sqlite3_bind_int64(ctx->stmt_offset, 3, file->db_offset_marker_size);
    sqlite3_bind_int64(ctx->stmt_offset, 4, file->db_id);

    ret = sqlite3_step(ctx->stmt_offset);

    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_offset);
        sqlite3_reset(ctx->stmt_offset);
        tail_db_unlock(ctx);
        return -1;
    }

    /* Verify number of updated rows */
    ret = sqlite3_changes(ctx->db->handler);
    if (ret == 0) {
        /*
         * 'someone' like you 'the reader' or another user has deleted the database
         * entry, just restore it.
         */
        file->db_id = db_file_insert(file, ctx);
    }

    sqlite3_clear_bindings(ctx->stmt_offset);
    sqlite3_reset(ctx->stmt_offset);

    tail_db_unlock(ctx);
    return 0;
}

/* Mark a file as rotated v2 */
int flb_tail_db_file_rotate(const char *new_name,
                            struct flb_tail_file *file,
                            struct flb_tail_config *ctx)
{
    int ret;

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_rotate_file, 1, new_name, -1, 0);
    sqlite3_bind_int64(ctx->stmt_rotate_file, 2, file->db_id);

    ret = sqlite3_step(ctx->stmt_rotate_file);

    sqlite3_clear_bindings(ctx->stmt_rotate_file);
    sqlite3_reset(ctx->stmt_rotate_file);

    if (ret != SQLITE_DONE) {
        tail_db_unlock(ctx);
        return -1;
    }

    tail_db_unlock(ctx);
    return 0;
}

/* Delete file entry from the database */
int flb_tail_db_file_delete(struct flb_tail_file *file,
                            struct flb_tail_config *ctx)
{
    int ret;

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_delete_file, 1, file->db_id);
    ret = sqlite3_step(ctx->stmt_delete_file);

    sqlite3_clear_bindings(ctx->stmt_delete_file);
    sqlite3_reset(ctx->stmt_delete_file);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error deleting entry from database: %s",
                      file->name);
        tail_db_unlock(ctx);
        return -1;
    }

    flb_plg_debug(ctx->ins, "db: file deleted from database: %s", file->name);
    tail_db_unlock(ctx);
    return 0;
}

int flb_tail_db_cleanup(struct flb_tail_config *ctx,
                        flb_tail_db_inode_check_fn inode_is_monitored,
                        void *data)
{
    int ret;
    int deleted_count;
    sqlite3_stmt *stmt_stale_files = NULL;

    if (ctx->db == NULL) {
        return 0;
    }

    /*
     * Only the original database context performs maintenance once for the
     * shared SQLite handler.
     */
    if (ctx->db->shared == FLB_TRUE) {
        return 0;
    }

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    ret = sqlite3_prepare_v2(ctx->db->handler, SQL_SELECT_STALE_FILES, -1,
                             &stmt_stale_files, 0);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "db: cannot prepare stale file query: ret=%d", ret);
        goto error;
    }

    ret = stale_file_delete_missing(ctx, inode_is_monitored, data,
                                    stmt_stale_files, &deleted_count);
    sqlite3_finalize(stmt_stale_files);
    stmt_stale_files = NULL;
    if (ret != 0) {
        goto error;
    }

    flb_plg_info(ctx->ins, "db: cleaned stale file records: count=%d",
                 deleted_count);
    tail_db_unlock(ctx);
    return 0;

error:
    if (stmt_stale_files != NULL) {
        sqlite3_finalize(stmt_stale_files);
    }
    tail_db_unlock(ctx);
    return -1;
}
