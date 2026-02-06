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

/* Callback to detect if a query returned any rows */
static int cb_column_exists(void *data, int argc, char **argv, char **cols)
{
    int *found = (int *)data;
    *found = 1;
    return 0;
}

/* Open or create database required by tail plugin */
struct flb_sqldb *flb_tail_db_open(const char *path,
                                   struct flb_input_instance *in,
                                   struct flb_tail_config *ctx,
                                   struct flb_config *config)
{
    int ret;
    int column_found;
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

    /* Check if 'skip' column exists (migration for older databases) */
    column_found = 0;
    ret = flb_sqldb_query(db,
                          "SELECT 1 FROM pragma_table_info('in_tail_files') "
                          "WHERE name='skip';",
                          cb_column_exists, &column_found);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: could not query table info for 'skip' column");
        flb_sqldb_close(db);
        return NULL;
    }
    if (column_found == 0) {
        flb_plg_debug(ctx->ins, "db: migrating database, adding 'skip' column");
        ret = flb_sqldb_query(db,
                              "ALTER TABLE in_tail_files "
                              "ADD COLUMN skip INTEGER DEFAULT 0;",
                              NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db: could not add 'skip' column");
            flb_sqldb_close(db);
            return NULL;
        }
    }

    /* Check if 'anchor' column exists (migration for older databases) */
    column_found = 0;
    ret = flb_sqldb_query(db,
                          "SELECT 1 FROM pragma_table_info('in_tail_files') "
                          "WHERE name='anchor';",
                          cb_column_exists, &column_found);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: could not query table info for 'anchor' column");
        flb_sqldb_close(db);
        return NULL;
    }
    if (column_found == 0) {
        flb_plg_debug(ctx->ins, "db: migrating database, adding 'anchor' column");
        ret = flb_sqldb_query(db,
                              "ALTER TABLE in_tail_files "
                              "ADD COLUMN anchor INTEGER DEFAULT 0;",
                              NULL, NULL);
        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "db: could not add 'anchor' column");
            flb_sqldb_close(db);
            return NULL;
        }
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
                          uint64_t *id, uint64_t *inode,
                          int64_t *offset, uint64_t *skip, int64_t *anchor)
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
            sqlite3_clear_bindings(ctx->stmt_get_file);
            sqlite3_reset(ctx->stmt_get_file);
            flb_plg_error(ctx->ins, "db: error getting name: id=%"PRIu64, *id);
            return -1;
        }

        /* offset: column 2 */
        *offset = sqlite3_column_int64(ctx->stmt_get_file, 2);

        /* inode: column 3 */
        *inode = sqlite3_column_int64(ctx->stmt_get_file, 3);

        /* skip: column 6 */
        *skip = sqlite3_column_int64(ctx->stmt_get_file, 6);

        /* anchor: column 7 */
        *anchor = sqlite3_column_int64(ctx->stmt_get_file, 7);

        /* Checking if the file's name and inode match exactly */
        if (ctx->compare_filename) {
            if (flb_tail_target_file_name_cmp((char *) name, file) != 0) {
                exists = FLB_FALSE;
                flb_plg_debug(ctx->ins, "db: exists stale file from database:"
                             " id=%"PRIu64" inode=%"PRIu64" offset=%"PRId64
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
    sqlite3_bind_int64(ctx->stmt_insert_file, 5, file->skip_bytes);
    sqlite3_bind_int64(ctx->stmt_insert_file, 6, file->anchor_offset);

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

int flb_tail_db_file_set(struct flb_tail_file *file,
                         struct flb_tail_config *ctx)
{
    int ret;
    uint64_t id = 0;
    int64_t offset = 0;
    uint64_t skip = 0;
    int64_t anchor = 0;
    uint64_t inode = 0;

    /* Check if the file exists */
    ret = db_file_exists(file, ctx, &id, &inode, &offset, &skip, &anchor);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot execute query to check inode: %" PRIu64,
                      file->inode);
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
        file->skip_bytes = skip;
        file->anchor_offset = anchor;

        /* Initialize skipping mode if needed */
        if (file->skip_bytes > 0) {
            file->exclude_bytes = file->skip_bytes;
            file->skipping_mode = FLB_TRUE;
        }
        else {
            file->exclude_bytes = 0;
            file->skipping_mode = FLB_FALSE;
        }
    }

    return 0;
}

/* Update Offset v2 */
int flb_tail_db_file_offset(struct flb_tail_file *file,
                            struct flb_tail_config *ctx)
{
    int ret;

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_offset, 1, file->offset);
    sqlite3_bind_int64(ctx->stmt_offset, 2, file->skip_bytes);
    sqlite3_bind_int64(ctx->stmt_offset, 3, file->anchor_offset);
    sqlite3_bind_int64(ctx->stmt_offset, 4, file->db_id);

    ret = sqlite3_step(ctx->stmt_offset);

    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_offset);
        sqlite3_reset(ctx->stmt_offset);
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

    return 0;
}

/* Mark a file as rotated v2 */
int flb_tail_db_file_rotate(const char *new_name,
                            struct flb_tail_file *file,
                            struct flb_tail_config *ctx)
{
    int ret;

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_rotate_file, 1, new_name, -1, 0);
    sqlite3_bind_int64(ctx->stmt_rotate_file, 2, file->db_id);

    ret = sqlite3_step(ctx->stmt_rotate_file);

    sqlite3_clear_bindings(ctx->stmt_rotate_file);
    sqlite3_reset(ctx->stmt_rotate_file);

    if (ret != SQLITE_DONE) {
        return -1;
    }

    return 0;
}

/* Delete file entry from the database */
int flb_tail_db_file_delete(struct flb_tail_file *file,
                            struct flb_tail_config *ctx)
{
    int ret;

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_delete_file, 1, file->db_id);
    ret = sqlite3_step(ctx->stmt_delete_file);

    sqlite3_clear_bindings(ctx->stmt_delete_file);
    sqlite3_reset(ctx->stmt_delete_file);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error deleting entry from database: %s",
                      file->name);
        return -1;
    }

    flb_plg_debug(ctx->ins, "db: file deleted from database: %s", file->name);
    file->db_id = FLB_TAIL_DB_ID_NONE;
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
    flb_sds_t stale_delete_sql;
    flb_sds_t sds_tmp;
    sqlite3_stmt *stmt_delete_inodes = NULL;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_file *file;

    if (!ctx->db) {
        return 0;
    }

    /* Create a stmt sql buffer */
    sql_size = SQL_DELETE_STALE_FILE_START_LEN;
    sql_size += SQL_DELETE_STALE_FILE_WHERE_LEN;
    sql_size += SQL_STMT_START_PARAM_LEN;
    sql_size += SQL_STMT_PARAM_END_LEN;
    sql_size += SQL_STMT_END_LEN;
    if (file_count > 0) {
        sql_size += (SQL_STMT_ADD_PARAM_LEN * file_count);
    }

    stale_delete_sql = flb_sds_create_size(sql_size + 1);
    if (!stale_delete_sql) {
        flb_plg_error(ctx->ins, "cannot allocate buffer for stale_delete_sql:"
                      " size: %zu", sql_size);
        return -1;
    }

    /* Create a stmt sql */
    sds_tmp = flb_sds_cat(stale_delete_sql, SQL_DELETE_STALE_FILE_START,
                          SQL_DELETE_STALE_FILE_START_LEN);
    if (sds_tmp == NULL) {
        flb_plg_error(ctx->ins,
                      "error concatenating stale_delete_sql: start");
        flb_sds_destroy(stale_delete_sql);
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
            return -1;
        }
        stale_delete_sql = sds_tmp;

        ret = stmt_add_param_concat(ctx, &stale_delete_sql, file_count);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "error concatenating stale_delete_sql: param");
            flb_sds_destroy(stale_delete_sql);
            return -1;
        }
    }

    sds_tmp = flb_sds_cat(stale_delete_sql, SQL_STMT_END, SQL_STMT_END_LEN);
    if (sds_tmp == NULL) {
        flb_plg_error(ctx->ins,
                      "error concatenating stale_delete_sql: end");
        flb_sds_destroy(stale_delete_sql);
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
        return -1;
    }

    ret = sqlite3_changes(ctx->db->handler);
    flb_plg_info(ctx->ins, "db: delete unmonitored stale inodes from the"
                 " database: count=%d", ret);

    sqlite3_finalize(stmt_delete_inodes);
    flb_sds_destroy(stale_delete_sql);

    return 0;
}
