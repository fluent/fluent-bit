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

#include "gcs.h"

#ifdef FLB_HAVE_SQLDB

#define SQL_CREATE_GCS_OBJECTS                                          \
    "CREATE TABLE IF NOT EXISTS in_gcs_objects ("                       \
    "  bucket     TEXT NOT NULL,"                                       \
    "  name       TEXT NOT NULL,"                                       \
    "  generation TEXT NOT NULL,"                                       \
    "  processed  INTEGER NOT NULL,"                                    \
    "  PRIMARY KEY (bucket, name, generation)"                          \
    ");"

#define SQL_GCS_OBJECT_EXISTS                                           \
    "SELECT 1 FROM in_gcs_objects "                                     \
    "  WHERE bucket=@bucket AND name=@name AND generation=@generation;"

#define SQL_GCS_OBJECT_INSERT                                           \
    "INSERT OR REPLACE INTO in_gcs_objects (bucket, name, generation, processed) "  \
    "  VALUES (@bucket, @name, @generation, @processed);"

int in_gcs_db_open(struct flb_in_gcs *ctx)
{
    int ret;

    if (!ctx->db_path) {
        return 0;
    }

    ctx->db = flb_sqldb_open(ctx->db_path, flb_input_name(ctx->ins), ctx->config);
    if (!ctx->db) {
        flb_plg_error(ctx->ins, "could not open/create the database '%s'", ctx->db_path);
        return -1;
    }

    ret = flb_sqldb_query(ctx->db, SQL_CREATE_GCS_OBJECTS, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: could not create the 'in_gcs_objects' table");
        return -1;
    }

    ret = sqlite3_prepare_v2(ctx->db->handler, SQL_GCS_OBJECT_EXISTS, -1,
                             &ctx->stmt_exists, 0);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "db: could not prepare the lookup statement");
        return -1;
    }

    ret = sqlite3_prepare_v2(ctx->db->handler, SQL_GCS_OBJECT_INSERT, -1,
                             &ctx->stmt_insert, 0);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "db: could not prepare the insert statement");
        return -1;
    }

    return 0;
}

void in_gcs_db_close(struct flb_in_gcs *ctx)
{
    if (ctx->stmt_exists) {
        sqlite3_finalize(ctx->stmt_exists);
        ctx->stmt_exists = NULL;
    }
    if (ctx->stmt_insert) {
        sqlite3_finalize(ctx->stmt_insert);
        ctx->stmt_insert = NULL;
    }
    if (ctx->db) {
        flb_sqldb_close(ctx->db);
        ctx->db = NULL;
    }
}

static void gcs_db_bind_key(struct flb_in_gcs *ctx, sqlite3_stmt *stmt, const char *name,
                            const char *generation)
{
    sqlite3_bind_text(stmt, 1, ctx->bucket, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, generation, -1, SQLITE_STATIC);
}

int in_gcs_db_has_object(struct flb_in_gcs *ctx, const char *name, const char *generation)
{
    int ret;
    int found = FLB_FALSE;

    if (!ctx->db) {
        return FLB_FALSE;
    }

    gcs_db_bind_key(ctx, ctx->stmt_exists, name, generation);
    ret = sqlite3_step(ctx->stmt_exists);
    if (ret == SQLITE_ROW) {
        found = FLB_TRUE;
    }
    else if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: lookup of '%s' failed", name);
    }
    sqlite3_clear_bindings(ctx->stmt_exists);
    sqlite3_reset(ctx->stmt_exists);

    return found;
}

int in_gcs_db_record_object(struct flb_in_gcs *ctx, const char *name, const char *generation)
{
    int ret;

    if (!ctx->db) {
        return 0;
    }

    gcs_db_bind_key(ctx, ctx->stmt_insert, name, generation);
    sqlite3_bind_int64(ctx->stmt_insert, 4, (sqlite3_int64) time(NULL));
    ret = sqlite3_step(ctx->stmt_insert);
    sqlite3_clear_bindings(ctx->stmt_insert);
    sqlite3_reset(ctx->stmt_insert);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: could not record '%s' (generation %s)", name,
                      generation);
        return -1;
    }

    return 0;
}

#else

/* no SQL support: the 'db' option does not exist and nothing is tracked */

int in_gcs_db_open(struct flb_in_gcs *ctx)
{
    (void) ctx;
    return 0;
}

void in_gcs_db_close(struct flb_in_gcs *ctx)
{
    (void) ctx;
}

int in_gcs_db_has_object(struct flb_in_gcs *ctx, const char *name, const char *generation)
{
    (void) ctx;
    (void) name;
    (void) generation;
    return FLB_FALSE;
}

int in_gcs_db_record_object(struct flb_in_gcs *ctx, const char *name, const char *generation)
{
    (void) ctx;
    (void) name;
    (void) generation;
    return 0;
}

#endif
