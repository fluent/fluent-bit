/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>

#ifdef FLB_HAVE_SQLDB

#include <fluent-bit/flb_sqldb.h>

#include "blob.h"
#include "blob_db.h"

static int prepare_stmts(struct flb_sqldb *db, struct blob_ctx *ctx)
{
    int ret;

    /* insert */
    ret = sqlite3_prepare_v2(db->handler, SQL_INSERT_FILE, -1,
                             &ctx->stmt_insert_file, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_INSERT_FILE);
        return -1;
    }

    /* delete */
    ret = sqlite3_prepare_v2(db->handler, SQL_DELETE_FILE, -1,
                             &ctx->stmt_delete_file, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_DELETE_FILE);
        return -1;
    }

    /* get */
    ret = sqlite3_prepare_v2(db->handler, SQL_GET_FILE, -1,
                             &ctx->stmt_get_file, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_GET_FILE);
        return -1;
    }

    return 0;
}
// static int my_special_callback(void *unused, int count, char **data, char **columns)
// {
//     int idx;

//     printf("There are %d column(s)\n", count);

//     for (idx = 0; idx < count; idx++) {
//         printf("The data in column \"%s\" is: %s\n", columns[idx], data[idx]);
//     }

//     printf("\n");

//     return 0;
// }

struct flb_sqldb *blob_db_open(struct blob_ctx *ctx, char *db_path)
{
    int ret;
    struct flb_sqldb *db;
    struct flb_input_instance *ins;

    ins = ctx->ins;

    db = flb_sqldb_open(db_path, ins->name, ctx->config);
    if (!db) {
        flb_plg_error(ctx->ins, "cannot open database %s", db_path);
        return NULL;
    }

    ret = flb_sqldb_query(db, SQL_CREATE_BLOB_FILES, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "cannot create table 'in_blob_files'");
        flb_sqldb_close(db);
        return NULL;
    }

    ret = prepare_stmts(db, ctx);
    if (ret == -1) {
        flb_sqldb_close(db);
        return NULL;
    }

    return db;
}

int blob_db_close(struct blob_ctx *ctx)
{
    int ret;

    if (ctx->db == NULL) {
        return 0;
    }

    /* finalize prepared statements */
    if (ctx->stmt_get_file != NULL) {
        sqlite3_finalize(ctx->stmt_get_file);
        ctx->stmt_get_file = NULL;
    }

    if (ctx->stmt_insert_file != NULL) {
        sqlite3_finalize(ctx->stmt_insert_file);
        ctx->stmt_insert_file = NULL;
    }

    if (ctx->stmt_delete_file != NULL) {
        sqlite3_finalize(ctx->stmt_delete_file);
        ctx->stmt_delete_file = NULL;
    }

    ret = flb_sqldb_close(ctx->db);
    ctx->db = NULL;

    return ret;
}

int blob_db_file_exists(struct blob_ctx *ctx, char *path, uint64_t *id)
{
    int ret;
    int exists = FLB_FALSE;

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_get_file, 1, path, -1, 0);
    ret = sqlite3_step(ctx->stmt_get_file);
    if (ret == SQLITE_ROW) {
        exists = FLB_TRUE;

        /* id: column 0 */
        *id = sqlite3_column_int64(ctx->stmt_get_file, 0);
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

int64_t blob_db_file_insert(struct blob_ctx *ctx, char *path, size_t size)
{
    int ret;
    int64_t id;
    time_t created;

    /* Register the file */
    created = time(NULL);

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_insert_file, 1, path, -1, 0);
    sqlite3_bind_int64(ctx->stmt_insert_file, 2, size);
    sqlite3_bind_int64(ctx->stmt_insert_file, 3, created);

    /* Run the insert */
    ret = sqlite3_step(ctx->stmt_insert_file);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_insert_file);
        sqlite3_reset(ctx->stmt_insert_file);
        flb_plg_error(ctx->ins, "cannot execute insert file '%s'", path);
        return -1;
    }

    /* Get the database ID for this file */
    id = flb_sqldb_last_id(ctx->db);

    sqlite3_clear_bindings(ctx->stmt_insert_file);
    sqlite3_reset(ctx->stmt_insert_file);


    flb_plg_trace(ctx->ins, "db: file '%s' inserted with id=%ld", path, id);
    return id;
}

int blob_db_file_delete(struct blob_ctx *ctx, uint64_t id, char *path)
{
    int ret;

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_delete_file, 1, id);
    ret = sqlite3_step(ctx->stmt_delete_file);
    if (ret != SQLITE_DONE) {
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_delete_file);
    sqlite3_reset(ctx->stmt_delete_file);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error deleting entry id=%" PRIu64
                      ", path='%s' from database", id, path);
        return -1;
    }

    flb_plg_debug(ctx->ins, "db: file id=%" PRIu64
                  ", path='%s' deleted from database", id, path);
    return 0;
}

#endif