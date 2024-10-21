/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>

#ifdef FLB_HAVE_SQLDB

#include <fluent-bit/flb_sqldb.h>

#include "azure_blob_db.h"

static int prepare_stmts(struct flb_sqldb *db, struct flb_azure_blob *ctx)
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

    /* abort */
    ret = sqlite3_prepare_v2(db->handler, SQL_SET_FILE_ABORTED_STATE, -1,
                             &ctx->stmt_set_file_aborted_state, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_SET_FILE_ABORTED_STATE);
        return -1;
    }

    /* file destination update  */
    ret = sqlite3_prepare_v2(db->handler,
                             SQL_UPDATE_FILE_DESTINATION, -1,
                             &ctx->stmt_update_file_destination,
                             NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_UPDATE_FILE_DESTINATION);
        return -1;
    }

    /* delivery attempt counter update  */
    ret = sqlite3_prepare_v2(db->handler,
                             SQL_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT, -1,
                             &ctx->stmt_update_file_delivery_attempt_count,
                             NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT);
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

    /* get next aborted file */
    ret = sqlite3_prepare_v2(db->handler, SQL_GET_NEXT_ABORTED_FILE, -1,
                             &ctx->stmt_get_next_aborted_file, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_GET_NEXT_ABORTED_FILE);
        return -1;
    }

    /* get next stale file */
    ret = sqlite3_prepare_v2(db->handler, SQL_GET_NEXT_STALE_FILE, -1,
                             &ctx->stmt_get_next_stale_file, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_GET_NEXT_STALE_FILE);
        return -1;
    }

    /* reset file upload progress */
    ret = sqlite3_prepare_v2(db->handler, SQL_RESET_FILE_UPLOAD_STATES, -1,
                             &ctx->stmt_reset_file_upload_states, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_RESET_FILE_UPLOAD_STATES);
        return -1;
    }

    /* reset file part upload progress */
    ret = sqlite3_prepare_v2(db->handler, SQL_RESET_FILE_PART_UPLOAD_STATES, -1,
                             &ctx->stmt_reset_file_part_upload_states, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_RESET_FILE_PART_UPLOAD_STATES);
        return -1;
    }

    /* insert blob file part */
    ret = sqlite3_prepare_v2(db->handler, SQL_INSERT_FILE_PART, -1,
                             &ctx->stmt_insert_file_part, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_INSERT_FILE_PART);
        return -1;
    }

    /* update blob part uploaded */
    ret = sqlite3_prepare_v2(db->handler, SQL_UPDATE_FILE_PART_UPLOADED, -1,
                             &ctx->stmt_update_file_part_uploaded, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_UPDATE_FILE_PART_UPLOADED);
        return -1;
    }

    ret = sqlite3_prepare_v2(db->handler, SQL_GET_NEXT_FILE_PART, -1,
                             &ctx->stmt_get_next_file_part, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_GET_NEXT_FILE_PART);
        return -1;
    }

    ret = sqlite3_prepare_v2(db->handler, SQL_UPDATE_FILE_PART_IN_PROGRESS, -1,
                             &ctx->stmt_update_file_part_in_progress, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_UPDATE_FILE_PART_IN_PROGRESS);
        return -1;
    }

    ret = sqlite3_prepare_v2(db->handler,
                             SQL_UPDATE_FILE_PART_DELIVERY_ATTEMPT_COUNT, -1,
                             &ctx->stmt_update_file_part_delivery_attempt_count,
                             NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_UPDATE_FILE_PART_DELIVERY_ATTEMPT_COUNT);
        return -1;
    }

    ret = sqlite3_prepare_v2(db->handler, SQL_GET_OLDEST_FILE_WITH_PARTS_CONCAT, -1,
                             &ctx->stmt_get_oldest_file_with_parts, NULL);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "cannot prepare SQL statement: %s",
                      SQL_GET_OLDEST_FILE_WITH_PARTS_CONCAT);
        return -1;
    }

    return 0;
}

static int azb_db_lock(struct flb_azure_blob *ctx)
{
    int ret;

    ret = pthread_mutex_lock(&ctx->db_lock);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot lock database mutex");
        return -1;
    }

    return 0;
}

static int azb_db_unlock(struct flb_azure_blob *ctx)
{
    int ret;

    ret = pthread_mutex_unlock(&ctx->db_lock);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot unlock database mutex");
        return -1;
    }

    return 0;
}

struct flb_sqldb *azb_db_open(struct flb_azure_blob *ctx, char *db_path)
{
    int ret;
    struct flb_sqldb *db;
    struct flb_output_instance *ins;

    ins = ctx->ins;

    db = flb_sqldb_open(db_path, ins->name, ctx->config);
    if (!db) {
        flb_plg_error(ctx->ins, "cannot open database %s", db_path);
        return NULL;
    }

    ret = flb_sqldb_query(db, SQL_CREATE_AZURE_BLOB_FILES, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "cannot create database tables");
        flb_sqldb_close(db);
        return NULL;
    }

    ret = flb_sqldb_query(db, SQL_CREATE_AZURE_BLOB_PARTS, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "cannot create database table for parts");
        flb_sqldb_close(db);
        return NULL;
    }

    ret = flb_sqldb_query(db, SQL_PRAGMA_FOREIGN_KEYS, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "cannot enable foreign keys");
        flb_sqldb_close(db);
        return NULL;
    }

    ret = prepare_stmts(db, ctx);
    if (ret == -1) {
        flb_sqldb_close(db);
        return NULL;
    }

    pthread_mutex_init(&ctx->db_lock, NULL);
    return db;
}

int azb_db_close(struct flb_azure_blob *ctx)
{
    if (ctx->db == NULL) {
        return 0;
    }

    /* finalize prepared statements */
    sqlite3_finalize(ctx->stmt_insert_file);
    sqlite3_finalize(ctx->stmt_delete_file);
    sqlite3_finalize(ctx->stmt_set_file_aborted_state);
    sqlite3_finalize(ctx->stmt_get_file);
    sqlite3_finalize(ctx->stmt_update_file_destination);
    sqlite3_finalize(ctx->stmt_update_file_delivery_attempt_count);
    sqlite3_finalize(ctx->stmt_get_next_aborted_file);
    sqlite3_finalize(ctx->stmt_get_next_stale_file);
    sqlite3_finalize(ctx->stmt_reset_file_upload_states);
    sqlite3_finalize(ctx->stmt_reset_file_part_upload_states);

    sqlite3_finalize(ctx->stmt_insert_file_part);
    sqlite3_finalize(ctx->stmt_update_file_part_uploaded);
    sqlite3_finalize(ctx->stmt_update_file_part_in_progress);
    sqlite3_finalize(ctx->stmt_update_file_part_delivery_attempt_count);

    sqlite3_finalize(ctx->stmt_get_next_file_part);
    sqlite3_finalize(ctx->stmt_get_oldest_file_with_parts);

    pthread_mutex_destroy(&ctx->db_lock);

    return flb_sqldb_close(ctx->db);
}

int azb_db_file_exists(struct flb_azure_blob *ctx, char *path, uint64_t *id)
{
    int ret;
    int exists = FLB_FALSE;

    azb_db_lock(ctx);

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

    azb_db_unlock(ctx);

    return exists;
}

int64_t azb_db_file_insert(struct flb_azure_blob *ctx,
                           char *source,
                           char *destination,
                           char *path,
                           size_t size)
{
    int ret;
    int64_t id;
    time_t created;

    /* Register the file */
    created = time(NULL);

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_insert_file, 1, source, -1, 0);
    sqlite3_bind_text(ctx->stmt_insert_file, 2, destination, -1, 0);
    sqlite3_bind_text(ctx->stmt_insert_file, 3, path, -1, 0);
    sqlite3_bind_int64(ctx->stmt_insert_file, 4, size);
    sqlite3_bind_int64(ctx->stmt_insert_file, 5, created);

    /* Run the insert */
    ret = sqlite3_step(ctx->stmt_insert_file);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_insert_file);
        sqlite3_reset(ctx->stmt_insert_file);
        flb_plg_error(ctx->ins, "cannot execute insert file '%s'", path);

        azb_db_unlock(ctx);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_insert_file);
    sqlite3_reset(ctx->stmt_insert_file);

    /* Get the database ID for this file */
    id = flb_sqldb_last_id(ctx->db);
    flb_plg_trace(ctx->ins, "db: file '%s' inserted with id=%ld", path, id);

    azb_db_unlock(ctx);

    return id;
}

int azb_db_file_delete(struct flb_azure_blob *ctx, uint64_t id, char *path)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_delete_file, 1, id);
    ret = sqlite3_step(ctx->stmt_delete_file);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_delete_file);
        sqlite3_reset(ctx->stmt_delete_file);
        azb_db_unlock(ctx);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_delete_file);
    sqlite3_reset(ctx->stmt_delete_file);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error deleting entry id=%" PRIu64
                      ", path='%s' from database", id, path);
        azb_db_unlock(ctx);
        return -1;
    }

    flb_plg_debug(ctx->ins, "db: file id=%" PRIu64
                  ", path='%s' deleted from database", id, path);

    azb_db_unlock(ctx);
    return 0;
}

int azb_db_file_set_aborted_state(struct flb_azure_blob *ctx,
                                  uint64_t id, char *path,
                                  uint64_t state)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_set_file_aborted_state, 1, state);
    sqlite3_bind_int64(ctx->stmt_set_file_aborted_state, 2, id);
    ret = sqlite3_step(ctx->stmt_set_file_aborted_state);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_set_file_aborted_state);
        sqlite3_reset(ctx->stmt_set_file_aborted_state);
        azb_db_unlock(ctx);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_set_file_aborted_state);
    sqlite3_reset(ctx->stmt_set_file_aborted_state);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error aborting entry id=%" PRIu64
                      ", path='%s' from database", id, path);
        azb_db_unlock(ctx);
        return -1;
    }

    flb_plg_debug(ctx->ins, "db: file id=%" PRIu64
                  ", path='%s' marked as aborted in the database", id, path);

    azb_db_unlock(ctx);
    return 0;
}

int azb_db_file_change_destination(struct flb_azure_blob *ctx, uint64_t id, cfl_sds_t destination)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_text(ctx->stmt_update_file_destination, 1, destination, -1, 0);
    sqlite3_bind_int64(ctx->stmt_update_file_destination, 2, id);

    /* Run the update */
    ret = sqlite3_step(ctx->stmt_update_file_destination);

    sqlite3_clear_bindings(ctx->stmt_update_file_destination);
    sqlite3_reset(ctx->stmt_update_file_destination);

    azb_db_unlock(ctx);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins,
                      "cannot update file destination "
                      "count for file id=%" PRIu64, id);

        return -1;
    }

    return 0;
}

int azb_db_file_delivery_attempts(struct flb_azure_blob *ctx,
                                  uint64_t id, uint64_t attempts)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_update_file_delivery_attempt_count, 1, attempts);
    sqlite3_bind_int64(ctx->stmt_update_file_delivery_attempt_count, 2, id);

    /* Run the update */
    ret = sqlite3_step(ctx->stmt_update_file_delivery_attempt_count);

    sqlite3_clear_bindings(ctx->stmt_update_file_delivery_attempt_count);
    sqlite3_reset(ctx->stmt_update_file_delivery_attempt_count);

    azb_db_unlock(ctx);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins,
                      "cannot update delivery attempt "
                      "count for file id=%" PRIu64, id);

        return -1;
    }

    return 0;
}

int azb_db_file_get_next_stale(struct flb_azure_blob *ctx,
                               uint64_t *id,
                               cfl_sds_t *path)
{
    int ret;
    char *tmp_path;
    int exists = FLB_FALSE;
    time_t freshness_threshold;

    freshness_threshold  = time(NULL);
    freshness_threshold -= ctx->upload_parts_freshness_threshold;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_get_next_stale_file, 1, freshness_threshold);
    ret = sqlite3_step(ctx->stmt_get_next_stale_file);
    if (ret == SQLITE_ROW) {
        exists = FLB_TRUE;

        /* id: column 0 */
        *id = sqlite3_column_int64(ctx->stmt_get_next_stale_file, 0);
        tmp_path = (char *) sqlite3_column_text(ctx->stmt_get_next_stale_file, 1);

        *path = cfl_sds_create(tmp_path);

        if (*path == NULL) {
            exists = -1;
        }
    }
    else if (ret == SQLITE_DONE) {
        /* all good */
    }
    else {
        exists = -1;
    }

    sqlite3_clear_bindings(ctx->stmt_get_next_stale_file);
    sqlite3_reset(ctx->stmt_get_next_stale_file);

    azb_db_unlock(ctx);

    if (exists == -1) {
        *id = 0;
        *path = NULL;
    }

    return exists;
}

int azb_db_file_get_next_aborted(struct flb_azure_blob *ctx,
                                 uint64_t *id,
                                 uint64_t *delivery_attempts,
                                 cfl_sds_t *path,
                                 cfl_sds_t *source)
{
    int ret;
    char *tmp_source;
    char *tmp_path;
    int exists = FLB_FALSE;

    azb_db_lock(ctx);

    /* Bind parameters */
    ret = sqlite3_step(ctx->stmt_get_next_aborted_file);
    if (ret == SQLITE_ROW) {
        exists = FLB_TRUE;

        /* id: column 0 */
        *id = sqlite3_column_int64(ctx->stmt_get_next_aborted_file, 0);
        *delivery_attempts = sqlite3_column_int64(ctx->stmt_get_next_aborted_file, 1);
        tmp_source = (char *) sqlite3_column_text(ctx->stmt_get_next_aborted_file, 2);
        tmp_path = (char *) sqlite3_column_text(ctx->stmt_get_next_aborted_file, 3);

        *path = cfl_sds_create(tmp_path);

        if (*path == NULL) {
            exists = -1;
        }
        else {
            *source = cfl_sds_create(tmp_source);
            if (*source == NULL) {
                cfl_sds_destroy(*path);
                exists = -1;
            }
        }
    }
    else if (ret == SQLITE_DONE) {
        /* all good */
    }
    else {
        exists = -1;
    }

    sqlite3_clear_bindings(ctx->stmt_get_next_aborted_file);
    sqlite3_reset(ctx->stmt_get_next_aborted_file);

    azb_db_unlock(ctx);

    if (exists == -1) {
        *id = 0;
        *delivery_attempts = 0;
        *path = NULL;
        *source = NULL;
    }

    return exists;
}


static int azb_db_file_reset_part_upload_states(struct flb_azure_blob *ctx, uint64_t id, char *path)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_reset_file_part_upload_states, 1, id);
    ret = sqlite3_step(ctx->stmt_reset_file_part_upload_states);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_reset_file_part_upload_states);
        sqlite3_reset(ctx->stmt_reset_file_part_upload_states);
        azb_db_unlock(ctx);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_reset_file_part_upload_states);
    sqlite3_reset(ctx->stmt_reset_file_part_upload_states);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error reseting upload "
                                "states for entry id=%" PRIu64
                                ", path='%s'", id, path);
        azb_db_unlock(ctx);
        return -1;
    }

    flb_plg_debug(ctx->ins, "db: file id=%" PRIu64
                  ", path='%s' upload states reset", id, path);

    azb_db_unlock(ctx);

    return 0;
}

int azb_db_file_reset_upload_states(struct flb_azure_blob *ctx, uint64_t id, char *path)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_reset_file_upload_states, 1, id);
    ret = sqlite3_step(ctx->stmt_reset_file_upload_states);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_reset_file_upload_states);
        sqlite3_reset(ctx->stmt_reset_file_upload_states);
        azb_db_unlock(ctx);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_reset_file_upload_states);
    sqlite3_reset(ctx->stmt_reset_file_upload_states);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins, "db: error reseting upload "
                                "states for entry id=%" PRIu64
                                ", path='%s'", id, path);
        azb_db_unlock(ctx);
        return -1;
    }

    flb_plg_debug(ctx->ins, "db: file id=%" PRIu64
                  ", path='%s' upload states reset", id, path);

    azb_db_unlock(ctx);

    return azb_db_file_reset_part_upload_states(ctx, id, path);
}

int azb_db_file_part_insert(struct flb_azure_blob *ctx, uint64_t file_id,
                            uint64_t part_id,
                            size_t offset_start, size_t offset_end,
                            int64_t *out_id)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_insert_file_part, 1, file_id);
    sqlite3_bind_int64(ctx->stmt_insert_file_part, 2, part_id);
    sqlite3_bind_int64(ctx->stmt_insert_file_part, 3, offset_start);
    sqlite3_bind_int64(ctx->stmt_insert_file_part, 4, offset_end);

    /* Run the insert */
    ret = sqlite3_step(ctx->stmt_insert_file_part);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_insert_file_part);
        sqlite3_reset(ctx->stmt_insert_file_part);
        flb_plg_error(ctx->ins, "cannot execute insert part for file_id=%" PRIu64,
                      file_id);

        azb_db_unlock(ctx);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_insert_file_part);
    sqlite3_reset(ctx->stmt_insert_file_part);

    azb_db_unlock(ctx);
    return 0;
}

int azb_db_file_part_in_progress(struct flb_azure_blob *ctx, int in_progress, uint64_t id)
{
    int ret;

    /* Bind parameters */
    sqlite3_bind_int(ctx->stmt_update_file_part_in_progress, 1, in_progress);
    sqlite3_bind_int64(ctx->stmt_update_file_part_in_progress, 2, id);

    /* Run the update */
    ret = sqlite3_step(ctx->stmt_update_file_part_in_progress);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_update_file_part_in_progress);
        sqlite3_reset(ctx->stmt_update_file_part_in_progress);
        flb_plg_error(ctx->ins, "cannot update part with id=%" PRIu64, id);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_update_file_part_in_progress);
    sqlite3_reset(ctx->stmt_update_file_part_in_progress);

    return 0;
}

/*
 * Retrieve the next part file that must be processed. Note tha this function will also lock
 * the file into the database to avoid any concurrency issue if multi workers are in use
 */
int azb_db_file_part_get_next(struct flb_azure_blob *ctx,
                              uint64_t *id, uint64_t *file_id, uint64_t *part_id,
                              off_t *offset_start, off_t *offset_end,
                              uint64_t *part_delivery_attempts,
                              uint64_t *file_delivery_attempts,
                              cfl_sds_t *file_path,
                              cfl_sds_t *destination)
{
    int ret;
    char *tmp = NULL;
    char *tmp_destination = NULL;
    cfl_sds_t path;
    cfl_sds_t local_destination;

    if (azb_db_lock(ctx) != 0) {
        return -1;
    }

    *file_path = NULL;

    /* Run the query */
    ret = sqlite3_step(ctx->stmt_get_next_file_part);
    if (ret == SQLITE_ROW) {
        *id = sqlite3_column_int64(ctx->stmt_get_next_file_part, 0);
        *file_id = sqlite3_column_int64(ctx->stmt_get_next_file_part, 1);
        *part_id = sqlite3_column_int64(ctx->stmt_get_next_file_part, 2);
        *offset_start = sqlite3_column_int64(ctx->stmt_get_next_file_part, 3);
        *offset_end = sqlite3_column_int64(ctx->stmt_get_next_file_part, 4);
        *part_delivery_attempts = sqlite3_column_int64(ctx->stmt_get_next_file_part, 5);
        tmp = (char *) sqlite3_column_text(ctx->stmt_get_next_file_part, 6);
        *file_delivery_attempts = sqlite3_column_int64(ctx->stmt_get_next_file_part, 7);
        tmp_destination = (char *) sqlite3_column_text(ctx->stmt_get_next_file_part, 9);
    }
    else if (ret == SQLITE_DONE) {
        /* no records */
        sqlite3_clear_bindings(ctx->stmt_get_next_file_part);
        sqlite3_reset(ctx->stmt_get_next_file_part);
        azb_db_unlock(ctx);
        return 0;
    }
    else {
        sqlite3_clear_bindings(ctx->stmt_get_next_file_part);
        sqlite3_reset(ctx->stmt_get_next_file_part);
        azb_db_unlock(ctx);
        return -1;
    }

    path = cfl_sds_create(tmp);
    local_destination = cfl_sds_create(tmp_destination);

    sqlite3_clear_bindings(ctx->stmt_get_next_file_part);
    sqlite3_reset(ctx->stmt_get_next_file_part);

    if (path == NULL || local_destination == NULL) {
        if (path != NULL) {
            cfl_sds_destroy(path);
        }

        if (local_destination != NULL) {
            cfl_sds_destroy(local_destination);
        }

        azb_db_unlock(ctx);
        return -1;
    }

    /* set the part flag 'in_progress' to '1' */
    ret = azb_db_file_part_in_progress(ctx, 1, *id);
    if (ret == -1) {
        cfl_sds_destroy(path);
        cfl_sds_destroy(local_destination);
        azb_db_unlock(ctx);
        return -1;
    }

    *file_path = path;
    *destination = local_destination;

    azb_db_unlock(ctx);

    return 1;
}

int azb_db_file_part_uploaded(struct flb_azure_blob *ctx, uint64_t id)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_update_file_part_uploaded, 1, id);

    /* Run the update */
    ret = sqlite3_step(ctx->stmt_update_file_part_uploaded);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_update_file_part_uploaded);
        sqlite3_reset(ctx->stmt_update_file_part_uploaded);
        flb_plg_error(ctx->ins, "cannot update part id=%" PRIu64, id);
        azb_db_unlock(ctx);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_update_file_part_uploaded);
    sqlite3_reset(ctx->stmt_update_file_part_uploaded);

    azb_db_unlock(ctx);

    return 0;
}

int azb_db_file_part_delivery_attempts(struct flb_azure_blob *ctx,
                                       uint64_t file_id,
                                       uint64_t part_id, uint64_t attempts)
{
    int ret;

    azb_db_lock(ctx);

    /* Bind parameters */
    sqlite3_bind_int64(ctx->stmt_update_file_part_delivery_attempt_count, 1, attempts);
    sqlite3_bind_int64(ctx->stmt_update_file_part_delivery_attempt_count, 2, file_id);
    sqlite3_bind_int64(ctx->stmt_update_file_part_delivery_attempt_count, 3, part_id);

    /* Run the update */
    ret = sqlite3_step(ctx->stmt_update_file_part_delivery_attempt_count);

    sqlite3_clear_bindings(ctx->stmt_update_file_part_delivery_attempt_count);
    sqlite3_reset(ctx->stmt_update_file_part_delivery_attempt_count);

    azb_db_unlock(ctx);

    if (ret != SQLITE_DONE) {
        flb_plg_error(ctx->ins,
                      "cannot update delivery attempt "
                      "count for part %" PRIu64 ".%" PRIu64,
                      file_id, part_id);

        return -1;
    }

    return 0;
}

int azb_db_file_oldest_ready(struct flb_azure_blob *ctx,
                             uint64_t *file_id, cfl_sds_t *path, cfl_sds_t *part_ids, cfl_sds_t *source)
{
    int ret;
    char *tmp = NULL;

    azb_db_lock(ctx);

    /* Run the query */
    ret = sqlite3_step(ctx->stmt_get_oldest_file_with_parts);
    if (ret == SQLITE_ROW) {
        /* file_id */
        *file_id = sqlite3_column_int64(ctx->stmt_get_oldest_file_with_parts, 0);
        tmp = (char *) sqlite3_column_text(ctx->stmt_get_oldest_file_with_parts, 1);

        /* path */
        *path = cfl_sds_create(tmp);
        if (!*path) {
            sqlite3_clear_bindings(ctx->stmt_get_oldest_file_with_parts);
            sqlite3_reset(ctx->stmt_get_oldest_file_with_parts);
            azb_db_unlock(ctx);
            return -1;
        }

        /* part_ids */
        tmp = (char *) sqlite3_column_text(ctx->stmt_get_oldest_file_with_parts, 2);
        *part_ids = cfl_sds_create(tmp);
        if (!*part_ids) {
            cfl_sds_destroy(*path);
            sqlite3_clear_bindings(ctx->stmt_get_oldest_file_with_parts);
            sqlite3_reset(ctx->stmt_get_oldest_file_with_parts);
            azb_db_unlock(ctx);
            return -1;
        }

        /* source */
        tmp = (char *) sqlite3_column_text(ctx->stmt_get_oldest_file_with_parts, 3);
        *source = cfl_sds_create(tmp);
        if (!*part_ids) {
            cfl_sds_destroy(*part_ids);
            cfl_sds_destroy(*path);
            sqlite3_clear_bindings(ctx->stmt_get_oldest_file_with_parts);
            sqlite3_reset(ctx->stmt_get_oldest_file_with_parts);
            azb_db_unlock(ctx);
            return -1;
        }
    }
    else if (ret == SQLITE_DONE) {
        /* no records */
        sqlite3_clear_bindings(ctx->stmt_get_oldest_file_with_parts);
        sqlite3_reset(ctx->stmt_get_oldest_file_with_parts);
        azb_db_unlock(ctx);
        return 0;
    }
    else {
        azb_db_unlock(ctx);
        return -1;
    }

    azb_db_unlock(ctx);
    return 1;
}

#endif