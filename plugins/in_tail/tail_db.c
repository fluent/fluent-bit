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

#include <inttypes.h>

struct query_status {
    int id;
    int rows;
    int64_t offset;
};

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

/*
 * Check if an file inode exists in the database.
 * If the 'compare_filename' option is enabled,
 * it checks along with the filename. Return FLB_TRUE or FLB_FALSE
 */
static int db_file_exists(struct flb_tail_file *file,
                          struct flb_tail_config *ctx,
                          uint64_t *id, uint64_t *inode, off_t *offset)
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

    /* Register the file */
    created = time(NULL);

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_insert_file, 1, file->name, -1, 0);
    sqlite3_bind_int64(ctx->stmt_insert_file, 2, file->offset);
    sqlite3_bind_int64(ctx->stmt_insert_file, 3, file->inode);
    sqlite3_bind_int64(ctx->stmt_insert_file, 4, created);

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

static int stmt_add_param_concat(struct flb_tail_config *ctx,
                                 flb_sds_t *stmt_sql, uint64_t count)
{
    uint64_t idx;
    flb_sds_t sds_tmp;

    sds_tmp = flb_sds_cat(*stmt_sql, SQL_STMT_START_PARAM,
                          SQL_STMT_START_PARAM_LEN);
    if (sds_tmp == NULL) {
        flb_plg_debug(ctx->ins, "error concatenating stmt_sql: param start");
        return -1;
    }
    *stmt_sql = sds_tmp;

    for (idx = 1; idx < count; idx++) {
        sds_tmp = flb_sds_cat(*stmt_sql, SQL_STMT_ADD_PARAM,
                              SQL_STMT_ADD_PARAM_LEN);
        if (sds_tmp == NULL) {
            flb_plg_debug(ctx->ins, "error concatenating stmt_sql: add param");
            return -1;
        }

        *stmt_sql = sds_tmp;
    }

    sds_tmp = flb_sds_cat(*stmt_sql, SQL_STMT_PARAM_END,
                          SQL_STMT_PARAM_END_LEN);
    if (sds_tmp == NULL) {
        flb_plg_debug(ctx->ins, "error concatenating stmt_sql: param end");
        return -1;
    }
    *stmt_sql = sds_tmp;

    return 0;
}

/*
 * Scalable stale inode cleanup: use a temp table to avoid SQLite variable limits.
 *
 * The legacy implementation builds:
 *   DELETE ... WHERE inode NOT IN (?,?,?,...);
 * which requires one bound parameter per inode and fails when the number of
 * monitored files exceeds SQLITE_LIMIT_VARIABLE_NUMBER (commonly 32766 in our
 * bundled SQLite, but can vary).
 */
static int flb_tail_db_stale_file_delete_temp_table(struct flb_tail_config *ctx,
                                                    uint64_t file_count,
                                                    int db_locked)
{
    int ret;
    int changes;
    int txn_started = FLB_FALSE;
    sqlite3_stmt *stmt_insert_inode = NULL;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_file *file;

    /* If there are no monitored files, delete everything from the DB table. */
    if (file_count == 0) {
        ret = flb_sqldb_query(ctx->db, "DELETE FROM in_tail_files;", NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db: cannot delete all stale inodes (no monitored files)");
            goto error;
        }

        changes = sqlite3_changes(ctx->db->handler);
        flb_plg_info(ctx->ins, "db: delete unmonitored stale inodes from the database: count=%d",
                     changes);
        if (db_locked == FLB_TRUE) {
            tail_db_unlock(ctx);
        }

        return 0;
    }

    /* Create/clear temp table holding current monitored inodes. */
    ret = flb_sqldb_query(ctx->db,
                          "CREATE TEMP TABLE IF NOT EXISTS in_tail_current_inodes ("
                          "  inode INTEGER PRIMARY KEY"
                          ");",
                          NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: cannot create temp table for inode cleanup");
        goto error;
    }

    ret = flb_sqldb_query(ctx->db, "DELETE FROM in_tail_current_inodes;", NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: cannot clear temp inode table");
        goto error;
    }

    /* Use a transaction for faster bulk inserts. */
    ret = flb_sqldb_query(ctx->db, "BEGIN;", NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: cannot begin transaction for temp inode inserts");
        goto error;
    }
    txn_started = FLB_TRUE;

    ret = sqlite3_prepare_v2(ctx->db->handler,
                             "INSERT OR IGNORE INTO in_tail_current_inodes(inode) VALUES (?);",
                             -1, &stmt_insert_inode, 0);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "db: cannot prepare temp inode insert statement, ret=%d", ret);
        goto error;
    }

    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        ret = sqlite3_bind_int64(stmt_insert_inode, 1, (sqlite3_int64) file->inode);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "db: error binding temp inode insert: inode=%" PRIu64 ", ret=%d",
                          file->inode, ret);
            goto error;
        }

        ret = sqlite3_step(stmt_insert_inode);
        if (ret != SQLITE_DONE) {
            flb_plg_error(ctx->ins, "db: error inserting inode into temp table: inode=%" PRIu64 ", ret=%d",
                          file->inode, ret);
            goto error;
        }

        sqlite3_clear_bindings(stmt_insert_inode);
        sqlite3_reset(stmt_insert_inode);
    }

    sqlite3_finalize(stmt_insert_inode);
    stmt_insert_inode = NULL;

    /* Delete any inode that is not in the current monitored set. */
    ret = flb_sqldb_query(ctx->db,
                          "DELETE FROM in_tail_files "
                          "WHERE inode NOT IN (SELECT inode FROM in_tail_current_inodes);",
                          NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: cannot delete stale inodes using temp table");
        goto error;
    }

    ret = flb_sqldb_query(ctx->db, "COMMIT;", NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: cannot commit transaction for temp inode inserts");
        goto error;
    }
    txn_started = FLB_FALSE;

    changes = sqlite3_changes(ctx->db->handler);
    flb_plg_info(ctx->ins, "db: delete unmonitored stale inodes from the database: count=%d",
                 changes);

    if (db_locked == FLB_TRUE) {
        tail_db_unlock(ctx);
    }

    return 0;

error:
    if (stmt_insert_inode) {
        sqlite3_finalize(stmt_insert_inode);
    }

    if (txn_started == FLB_TRUE) {
        /* Best-effort rollback */
        flb_sqldb_query(ctx->db, "ROLLBACK;", NULL, NULL);
    }

    if (db_locked == FLB_TRUE) {
        tail_db_unlock(ctx);
    }

    return -1;
}

int flb_tail_db_file_set(struct flb_tail_file *file,
                         struct flb_tail_config *ctx)
{
    int ret;
    uint64_t id = 0;
    off_t offset = 0;
    uint64_t inode = 0;

    flb_plg_debug(ctx->ins, "db file set called for %s inode=%"PRIu64,
                  file->name, file->inode);

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    /* Check if the file exists */
    ret = db_file_exists(file, ctx, &id, &inode, &offset);
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
    }

    tail_db_unlock(ctx);
    return 0;
}

/* Update Offset v2 */
int flb_tail_db_file_offset(struct flb_tail_file *file,
                            struct flb_tail_config *ctx)
{
    int ret;

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_offset, 1, file->offset);
    sqlite3_bind_int64(ctx->stmt_offset, 2, file->db_id);

    ret = sqlite3_step(ctx->stmt_offset);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins,
                      "db: cannot update file offset for %s (id=%"PRIu64"), ret=%d",
                      file->name, file->db_id, ret);
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

/*
 * Delete stale file from database
 */
int flb_tail_db_stale_file_delete(struct flb_input_instance *ins,
                                  struct flb_config *config,
                                  struct flb_tail_config *ctx)
{
    int ret = -1;
    size_t sql_size;
    uint64_t idx;
    uint64_t file_count = ctx->files_static_count;
    int max_vars = -1;
    flb_sds_t stale_delete_sql;
    flb_sds_t sds_tmp;
    sqlite3_stmt *stmt_delete_inodes = NULL;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_file *file;
    int db_locked = FLB_FALSE;

    if (!ctx->db) {
        return 0;
    }

    ret = tail_db_lock(ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "db: could not acquire lock");
        return -1;
    }

    db_locked = FLB_TRUE;

    /*
     * Avoid SQLite variable limits for large monitored file sets.
     *
     * sqlite3_limit(..., SQLITE_LIMIT_VARIABLE_NUMBER, -1) returns the current
     * runtime limit (compile-time hard limit may be higher). If our monitored
     * file count exceeds this, the legacy NOT IN (?,?,...) statement will fail
     * at prepare-time.
     */
    max_vars = sqlite3_limit(ctx->db->handler, SQLITE_LIMIT_VARIABLE_NUMBER, -1);
    if (max_vars > 0 && file_count > (uint64_t) max_vars) {
        flb_plg_warn(ctx->ins,
                     "db: large file set detected (%" PRIu64 " files) exceeds SQLite variable limit (%d); "
                     "using temp-table cleanup for stale inode deletion",
                     file_count, max_vars);
        return flb_tail_db_stale_file_delete_temp_table(ctx, file_count, db_locked);
    }

    /* Create a stmt sql buffer */
    sql_size = SQL_DELETE_STALE_FILE_START_LEN;
    sql_size += SQL_DELETE_STALE_FILE_WHERE_LEN;
    sql_size += SQL_STMT_START_PARAM_LEN;
    sql_size += SQL_STMT_PARAM_END_LEN;
    sql_size += SQL_STMT_END_LEN;
    if (file_count > 0) {
        /*
         * We already account for the first '?' via SQL_STMT_START_PARAM_LEN.
         * Additional parameters are count-1 occurrences of ",?".
         */
        if (file_count > 1) {
            sql_size += (SQL_STMT_ADD_PARAM_LEN * (file_count - 1));
        }
    }

    stale_delete_sql = flb_sds_create_size(sql_size + 1);
    if (!stale_delete_sql) {
        flb_plg_error(ctx->ins, "cannot allocate buffer for stale_delete_sql:"
                      " size: %zu", sql_size);
        if (db_locked == FLB_TRUE) {
            tail_db_unlock(ctx);
        }

        return -1;
    }

    /* Create a stmt sql */
    sds_tmp = flb_sds_cat(stale_delete_sql, SQL_DELETE_STALE_FILE_START,
                          SQL_DELETE_STALE_FILE_START_LEN);
    if (sds_tmp == NULL) {
        flb_plg_error(ctx->ins,
                      "error concatenating stale_delete_sql: start");
        flb_sds_destroy(stale_delete_sql);
        if (db_locked == FLB_TRUE) {
            tail_db_unlock(ctx);
        }

        return -1;
    }
    stale_delete_sql = sds_tmp;

    if (file_count > 0) {
        sds_tmp = flb_sds_cat(stale_delete_sql, SQL_DELETE_STALE_FILE_WHERE,
                              SQL_DELETE_STALE_FILE_WHERE_LEN);
        if (sds_tmp == NULL) {
            flb_plg_error(ctx->ins,
                          "error concatenating stale_delete_sql: where");
            flb_sds_destroy(stale_delete_sql);
            if (db_locked == FLB_TRUE) {
                tail_db_unlock(ctx);
            }

            return -1;
        }
        stale_delete_sql = sds_tmp;

        ret = stmt_add_param_concat(ctx, &stale_delete_sql, file_count);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "error concatenating stale_delete_sql: param");
            flb_sds_destroy(stale_delete_sql);
            if (db_locked == FLB_TRUE) {
                tail_db_unlock(ctx);
            }

            return -1;
        }
    }

    sds_tmp = flb_sds_cat(stale_delete_sql, SQL_STMT_END, SQL_STMT_END_LEN);
    if (sds_tmp == NULL) {
        flb_plg_error(ctx->ins,
                      "error concatenating stale_delete_sql: end");
        flb_sds_destroy(stale_delete_sql);
        if (db_locked == FLB_TRUE) {
            tail_db_unlock(ctx);
        }

        return -1;
    }
    stale_delete_sql = sds_tmp;

    /* Prepare stmt */
    ret = sqlite3_prepare_v2(ctx->db->handler, stale_delete_sql, -1,
                             &stmt_delete_inodes, 0);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "error preparing database SQL statement:"
                      " stmt_delete_inodes sql:%s, ret=%d", stale_delete_sql,
                      ret);
        flb_sds_destroy(stale_delete_sql);
        if (db_locked == FLB_TRUE) {
            tail_db_unlock(ctx);
        }

        return -1;
    }

    /* Bind parameters */
    idx = 1;
    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        ret = sqlite3_bind_int64(stmt_delete_inodes, idx, file->inode);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error binding to stmt_delete_inodes:"
                          " inode=%" PRIu64 ", ret=%d", file->inode, ret);
            sqlite3_finalize(stmt_delete_inodes);
            flb_sds_destroy(stale_delete_sql);
            if (db_locked == FLB_TRUE) {
                tail_db_unlock(ctx);
            }

            return -1;
        }
        idx++;
    }

    /* Run the delete inodes */
    ret = sqlite3_step(stmt_delete_inodes);
    if (ret != SQLITE_DONE) {
        sqlite3_finalize(stmt_delete_inodes);
        flb_sds_destroy(stale_delete_sql);
        flb_plg_error(ctx->ins, "cannot execute delete stale inodes: ret=%d",
                      ret);

        if (db_locked == FLB_TRUE) {
            tail_db_unlock(ctx);
        }

        return -1;
    }

    ret = sqlite3_changes(ctx->db->handler);
    flb_plg_info(ctx->ins, "db: delete unmonitored stale inodes from the"
                 " database: count=%d", ret);

    sqlite3_finalize(stmt_delete_inodes);
    flb_sds_destroy(stale_delete_sql);

    if (db_locked == FLB_TRUE) {
        tail_db_unlock(ctx);
    }

    db_locked = FLB_FALSE;

    return 0;
}
