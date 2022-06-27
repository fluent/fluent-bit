/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

struct query_status {
    int id;
    int rows;
    int64_t offset;
};

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

/*
 * Check if an file inode exists in the database. Return FLB_TRUE or
 * FLB_FALSE
 */
static int db_file_exists(struct flb_tail_file *file,
                          struct flb_tail_config *ctx,
                          uint64_t *id, uint64_t *inode, off_t *offset)
{
    int ret;
    int exists = FLB_FALSE;

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_get_file, 1, file->inode);
    ret = sqlite3_step(ctx->stmt_get_file);

    if (ret == SQLITE_ROW) {
        exists = FLB_TRUE;

        /* id: column 0 */
        *id = sqlite3_column_int64(ctx->stmt_get_file, 0);

        /* offset: column 2 */
        *offset = sqlite3_column_int64(ctx->stmt_get_file, 2);

        /* inode: column 3 */
        *inode = sqlite3_column_int64(ctx->stmt_get_file, 3);
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
        flb_plg_error(ctx->ins, "cannot execute insert file %s inode=%lu",
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

    /* Check if the file exists */
    ret = db_file_exists(file, ctx, &id, &inode, &offset);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "cannot execute query to check inode: %lu",
                      file->inode);
        return -1;
    }

    if (ret == FLB_FALSE) {
        /* Get the database ID for this file */
        file->db_id = db_file_insert(file, ctx);
    }
    else {
        file->db_id = id;
        file->offset = offset;
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
    sqlite3_bind_int64(ctx->stmt_offset, 2, file->db_id);

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
    return 0;
}
