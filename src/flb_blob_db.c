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

#ifdef FLB_HAVE_SQLDB

#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_blob_db.h>

static int prepare_stmts(struct flb_blob_db *context)
{
    int result;

    /* insert */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_INSERT_FILE, -1,
                                &context->stmt_insert_file,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_INSERT_FILE;
    }

    /* delete */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_DELETE_FILE, -1,
                                &context->stmt_delete_file,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_DELETE_FILE;
    }

    /* abort */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_SET_FILE_ABORTED_STATE, -1,
                                &context->stmt_set_file_aborted_state,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_ABORT_FILE;
    }


    /* file remote id update  */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_UPDATE_FILE_REMOTE_ID, -1,
                                &context->stmt_update_file_remote_id,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_REMOTE_ID;
    }

    /* file destination update  */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_UPDATE_FILE_DESTINATION, -1,
                                &context->stmt_update_file_destination,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_DESTINATION;
    }

    /* delivery attempt counter update  */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT, -1,
                                &context->stmt_update_file_delivery_attempt_count,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT;
    }

    /* get */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_GET_FILE, -1,
                                &context->stmt_get_file,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_FILE;
    }

    /* get part count */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_GET_FILE_PART_COUNT, -1,
                                &context->stmt_get_file_part_count,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_FILE_PART_COUNT;
    }

    /* get next aborted file */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_GET_NEXT_ABORTED_FILE, -1,
                                &context->stmt_get_next_aborted_file,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_NEXT_ABORTED_FILE;
    }

    /* get next stale file */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_GET_NEXT_STALE_FILE, -1,
                                &context->stmt_get_next_stale_file,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_NEXT_STALE_FILE;
    }

    /* reset file upload progress */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_RESET_FILE_UPLOAD_STATES, -1,
                                &context->stmt_reset_file_upload_states,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_RESET_FILE_UPLOAD_STATES;
    }

    /* reset file part upload progress */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_RESET_FILE_PART_UPLOAD_STATES, -1,
                                &context->stmt_reset_file_part_upload_states,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_RESET_FILE_PART_UPLOAD_STATES;
    }

    /* insert blob file part */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_INSERT_FILE_PART, -1,
                                &context->stmt_insert_file_part,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_INSERT_FILE_PART;
    }

    /* update blob part remote id */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_UPDATE_FILE_PART_REMOTE_ID, -1,
                                &context->stmt_update_file_part_remote_id,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_PART_REMOTE_ID;
    }

    /* fetch blob part remote id */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_GET_FILE_PART_REMOTE_ID, -1,
                                &context->stmt_fetch_file_part_remote_id,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_FETCH_FILE_PART_REMOTE_ID;
    }

    /* update blob part uploaded */
    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_UPDATE_FILE_PART_UPLOADED, -1,
                                &context->stmt_update_file_part_uploaded,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_PART_UPLOADED;
    }

    /* get next file part to upload */

    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_GET_NEXT_FILE_PART, -1,
                                &context->stmt_get_next_file_part,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_NEXT_FILE_PART;
    }

    /* update file part upload in progress flag */

    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_UPDATE_FILE_PART_IN_PROGRESS, -1,
                                &context->stmt_update_file_part_in_progress,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_PART_IN_PROGRESS;
    }

    /* update file part delivery attempt counter */

    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_UPDATE_FILE_PART_DELIVERY_ATTEMPT_COUNT, -1,
                                &context->stmt_update_file_part_delivery_attempt_count,
                                NULL);
    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT;
    }

    /* get the oldest (fifo) file available to commit */

    result = sqlite3_prepare_v2(context->db->handler,
                                SQL_GET_OLDEST_FILE_WITH_PARTS_CONCAT, -1,
                                &context->stmt_get_oldest_file_with_parts,
                                NULL);

    if (result != SQLITE_OK) {
        return FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_OLDEST_FILE_WITH_PARTS;
    }

    return FLB_BLOB_DB_SUCCESS;
}

int flb_blob_db_open(struct flb_blob_db *context,
                     struct flb_config *config,
                     char *path)
{
    int               result;
    struct flb_sqldb *db;

    if (context == NULL) {
        return FLB_BLOB_DB_ERROR_INVALID_BLOB_DB_CONTEXT;
    }

    if (config == NULL) {
        return FLB_BLOB_DB_ERROR_INVALID_FLB_CONTEXT;
    }

    if (path == NULL) {
        return FLB_BLOB_DB_ERROR_INVALID_DATABASE_PATH;
    }

    db = flb_sqldb_open(path, "", config);

    if (db == NULL) {
        return FLB_BLOB_DB_ERROR_SQLDB_OPEN_FAILURE;
    }

    result = flb_sqldb_query(db, SQL_CREATE_BLOB_FILES, NULL, NULL);

    if (result != FLB_OK) {
        flb_sqldb_close(db);

        return FLB_BLOB_DB_ERROR_FILE_TABLE_CREATION;
    }

    result = flb_sqldb_query(db, SQL_CREATE_BLOB_PARTS, NULL, NULL);

    if (result != FLB_OK) {
        flb_sqldb_close(db);

        return FLB_BLOB_DB_ERROR_PART_TABLE_CREATION;
    }

    result = flb_sqldb_query(db, SQL_PRAGMA_FOREIGN_KEYS, NULL, NULL);

    if (result != FLB_OK) {
        flb_sqldb_close(db);

        return FLB_BLOB_DB_ERROR_SQLDB_FK_INIT_FAILURE;
    }

    result = flb_lock_init(&context->global_lock);

    if (result != 0) {
        flb_sqldb_close(db);

        return FLB_BLOB_DB_ERROR_LOCK_INIT;
    }

    context->db = db;

    result = prepare_stmts(context);

    if (result != FLB_BLOB_DB_SUCCESS) {
        flb_lock_destroy(&context->global_lock);
        flb_sqldb_close(db);

        context->db = NULL;
    }

    return result;
}

int flb_blob_db_close(struct flb_blob_db *context)
{
    int result;

    if (context == NULL) {
        return FLB_BLOB_DB_ERROR_INVALID_BLOB_DB_CONTEXT;
    }

    if (context->db == NULL) {
        return FLB_BLOB_DB_SUCCESS;
    }

    /* finalize prepared statements */
    sqlite3_finalize(context->stmt_insert_file);
    sqlite3_finalize(context->stmt_delete_file);
    sqlite3_finalize(context->stmt_set_file_aborted_state);
    sqlite3_finalize(context->stmt_get_file);
    sqlite3_finalize(context->stmt_get_file_part_count);
    sqlite3_finalize(context->stmt_update_file_remote_id);
    sqlite3_finalize(context->stmt_update_file_destination);
    sqlite3_finalize(context->stmt_update_file_delivery_attempt_count);
    sqlite3_finalize(context->stmt_get_next_aborted_file);
    sqlite3_finalize(context->stmt_get_next_stale_file);
    sqlite3_finalize(context->stmt_reset_file_upload_states);
    sqlite3_finalize(context->stmt_reset_file_part_upload_states);

    sqlite3_finalize(context->stmt_insert_file_part);
    sqlite3_finalize(context->stmt_update_file_part_remote_id);
    sqlite3_finalize(context->stmt_fetch_file_part_remote_id);
    sqlite3_finalize(context->stmt_update_file_part_uploaded);
    sqlite3_finalize(context->stmt_update_file_part_in_progress);
    sqlite3_finalize(context->stmt_update_file_part_delivery_attempt_count);

    sqlite3_finalize(context->stmt_get_next_file_part);
    sqlite3_finalize(context->stmt_get_oldest_file_with_parts);

    flb_lock_destroy(&context->global_lock);

    result = flb_sqldb_close(context->db);

    context->db = NULL;

    return result;
}

int flb_blob_db_lock(struct flb_blob_db *context)
{
    return flb_lock_acquire(&context->global_lock,
                            FLB_LOCK_INFINITE_RETRY_LIMIT,
                            FLB_LOCK_DEFAULT_RETRY_DELAY);
}

int flb_blob_db_unlock(struct flb_blob_db *context)
{
    return flb_lock_release(&context->global_lock,
                            FLB_LOCK_INFINITE_RETRY_LIMIT,
                            FLB_LOCK_DEFAULT_RETRY_DELAY);
}


int flb_blob_db_file_exists(struct flb_blob_db *context,
                            char *path,
                            uint64_t *id)
{
    sqlite3_stmt *statement;
    int           result;
    int           exists;

    statement = context->stmt_get_file;

    flb_sqldb_lock(context->db);

    /* Bind parameters */
    sqlite3_bind_text(statement, 1, path, -1, 0);

    result = sqlite3_step(statement);

    if (result == SQLITE_ROW) {
        exists = FLB_TRUE;

        /* id: column 0 */
        *id = sqlite3_column_int64(statement, 0);
    }
    else if (result == SQLITE_DONE) {
        exists = FLB_FALSE;
    }
    else {
        exists = -1;
    }

    sqlite3_clear_bindings(statement);

    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return exists;
}

int64_t flb_blob_db_file_insert(struct flb_blob_db *context,
                                char *tag,
                                char *source,
                                char *destination,
                                char *path,
                                size_t size)
{
    sqlite3_stmt *statement;
    time_t        created;
    int           result;
    int64_t       id;

    statement = context->stmt_insert_file;

    flb_sqldb_lock(context->db);

    created = time(NULL);

    sqlite3_bind_text(statement,  1, tag, -1, 0);
    sqlite3_bind_text(statement,  2, source, -1, 0);
    sqlite3_bind_text(statement,  3, destination, -1, 0);
    sqlite3_bind_text(statement,  4, path, -1, 0);
    sqlite3_bind_int64(statement, 5, size);
    sqlite3_bind_int64(statement, 6, created);

    result = sqlite3_step(statement);

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    if (result == SQLITE_DONE) {
        /* Get the database ID for this file */
        id = flb_sqldb_last_id(context->db);
    }
    else {
        context->last_error = result;

        id = FLB_BLOB_DB_ERROR_FILE_INSERT;
    }

    flb_sqldb_unlock(context->db);

    return id;
}

int flb_blob_db_file_delete(struct flb_blob_db *context,
                            uint64_t id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_delete_file;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_DELETE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_set_aborted_state(struct flb_blob_db *context,
                                       uint64_t id,
                                       uint64_t state)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_set_file_aborted_state;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, state);
    sqlite3_bind_int64(statement, 2, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_ABORT;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_file_update_remote_id(struct flb_blob_db *context,
                                   uint64_t id,
                                   cfl_sds_t remote_id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_update_file_remote_id;

    flb_sqldb_lock(context->db);

    sqlite3_bind_text(statement, 1, remote_id, -1, 0);
    sqlite3_bind_int64(statement, 2, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_REMOTE_ID_UPDATE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_file_change_destination(struct flb_blob_db *context,
                                     uint64_t id,
                                     cfl_sds_t destination)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_update_file_destination;

    flb_sqldb_lock(context->db);

    sqlite3_bind_text(statement, 1, destination, -1, 0);
    sqlite3_bind_int64(statement, 2, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_DESTINATION_CHANGE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_delivery_attempts(struct flb_blob_db *context,
                                       uint64_t id,
                                       uint64_t attempts)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_update_file_delivery_attempt_count;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, attempts);
    sqlite3_bind_int64(statement, 2, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_DELIVERY_ATTEMPT_UPDATE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_get_next_stale(struct flb_blob_db *context,
                                    uint64_t *id,
                                    cfl_sds_t *path,
                                    uint64_t upload_parts_freshness_threshold,
                                    cfl_sds_t *remote_id,
                                    cfl_sds_t *tag,
                                    int *part_count)
{
    time_t        freshness_threshold;
    sqlite3_stmt *statement;
    char         *tmp_remote_id;
    char         *tmp_path;
    char         *tmp_tag;
    int           exists;
    int           result;

    statement = context->stmt_get_next_stale_file;

    flb_sqldb_lock(context->db);

    freshness_threshold  = time(NULL) - upload_parts_freshness_threshold;

    sqlite3_bind_int64(statement, 1, freshness_threshold);

    result = sqlite3_step(statement);

    if (result == SQLITE_ROW) {
        exists = FLB_TRUE;

        *id = sqlite3_column_int64(statement, 0);
        tmp_path = (char *) sqlite3_column_text(statement, 1);
        tmp_remote_id = (char *) sqlite3_column_text(statement, 2);
        tmp_tag = (char *) sqlite3_column_text(statement, 3);

        *path = cfl_sds_create(tmp_path);

        if (*path == NULL) {
            exists = -1;
        }
        else {
            *remote_id = cfl_sds_create(tmp_remote_id);

            if (*remote_id == NULL) {
                exists = -1;
            }
            else {
                *tag = cfl_sds_create(tmp_tag);

                if (*tag == NULL) {
                    exists = -1;
                }
                else {
                    *part_count = flb_blob_db_file_fetch_part_count(context, *id);

                    if (*part_count <= 0) {
                        exists = -1;
                    }
                    else {
                        exists = 1;
                    }

                }
            }
        }
    }
    else if (result == SQLITE_DONE) {
        exists = FLB_FALSE;
    }
    else {
        context->last_error = result;

        exists = -1;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    if (exists == -1) {
        if (*path != NULL) {
            cfl_sds_destroy(*path);

            *path = NULL;
        }

        if (*remote_id != NULL) {
            cfl_sds_destroy(*remote_id);

            *remote_id = NULL;
        }

        if (*tag != NULL) {
            cfl_sds_destroy(*tag);

            *tag = NULL;
        }

        *id = 0;
    }

    flb_sqldb_unlock(context->db);

    return exists;
}

int flb_blob_db_file_get_next_aborted(struct flb_blob_db *context,
                                      uint64_t *id,
                                      uint64_t *delivery_attempts,
                                      cfl_sds_t *path,
                                      cfl_sds_t *source,
                                      cfl_sds_t *remote_id,
                                      cfl_sds_t *file_tag,
                                      int *part_count)
{
    char         *tmp_remote_id;
    char         *tmp_source;
    sqlite3_stmt *statement;
    char         *tmp_path;
    char         *tmp_tag;
    int           result;
    int           exists;

    *path = NULL;
    *source = NULL;
    *remote_id = NULL;
    *file_tag = NULL;

    statement = context->stmt_get_next_aborted_file;

    flb_sqldb_lock(context->db);

    result = sqlite3_step(statement);

    if (result == SQLITE_ROW) {
        exists = FLB_TRUE;

        *id = sqlite3_column_int64(statement, 0);
        *delivery_attempts = sqlite3_column_int64(statement, 1);
        tmp_source = (char *) sqlite3_column_text(statement, 2);
        tmp_path = (char *) sqlite3_column_text(statement, 3);
        tmp_remote_id = (char *) sqlite3_column_text(statement, 4);
        tmp_tag = (char *) sqlite3_column_text(statement, 5);

        *path = cfl_sds_create(tmp_path);

        if (*path == NULL) {
            exists = -1;
        }
        else {
            *source = cfl_sds_create(tmp_source);

            if (*source == NULL) {
                exists = -1;
            }
            else {
                *remote_id = cfl_sds_create(tmp_remote_id);

                if (*remote_id == NULL) {
                    exists = -1;
                }
                else {
                    *file_tag = cfl_sds_create(tmp_tag);

                    if (*file_tag == NULL) {
                        exists = -1;
                    }
                    else {
                        *part_count = flb_blob_db_file_fetch_part_count(context, *id);

                        if (*part_count <= 0) {
                            exists = -1;
                        }
                        else {
                            exists = 1;
                        }
                    }
                }
            }
        }
    }
    else if (result == SQLITE_DONE) {
        exists = FLB_FALSE;
    }
    else {
        context->last_error = result;

        exists = -1;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    if (exists == -1) {
        *id = 0;
        *delivery_attempts = 0;

        if (*path != NULL) {
            cfl_sds_destroy(*path);
            *path = NULL;
        }

        if (*source != NULL) {
            cfl_sds_destroy(*source);
            *source = NULL;
        }

        if (*remote_id != NULL) {
            cfl_sds_destroy(*remote_id);
            *remote_id = NULL;
        }

        if (*file_tag != NULL) {
            cfl_sds_destroy(*file_tag);
            *file_tag = NULL;
        }
    }

    return exists;
}


static int flb_blob_db_file_reset_part_upload_states(struct flb_blob_db *context,
                                                     uint64_t id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_reset_file_part_upload_states;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_PART_UPLOAD_STATE_RESET;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);

    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_reset_upload_states(struct flb_blob_db *context,
                                         uint64_t id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_reset_file_upload_states;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, id);

    result = sqlite3_step(statement);

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_UPLOAD_STATE_RESET;
    }
    else {
        result = flb_blob_db_file_reset_part_upload_states(context, id);
    }

    return result;
}

int flb_blob_db_file_part_insert(struct flb_blob_db *context,
                                 uint64_t file_id,
                                 uint64_t part_id,
                                 size_t offset_start,
                                 size_t offset_end,
                                 int64_t *out_id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_insert_file_part;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, file_id);
    sqlite3_bind_int64(statement, 2, part_id);
    sqlite3_bind_int64(statement, 3, offset_start);
    sqlite3_bind_int64(statement, 4, offset_end);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_PART_INSERT;

        *out_id = -1;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;

        *out_id = flb_sqldb_last_id(context->db);
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_part_in_progress(struct flb_blob_db *context,
                                      int in_progress,
                                      uint64_t id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_update_file_part_in_progress;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int(statement, 1, in_progress);
    sqlite3_bind_int64(statement, 2, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_FILE_PART_IN_PROGRESS_UPDATE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_part_get_next(struct flb_blob_db *context,
                                   uint64_t *id,
                                   uint64_t *file_id,
                                   uint64_t *part_id,
                                   off_t *offset_start,
                                   off_t *offset_end,
                                   uint64_t *part_delivery_attempts,
                                   uint64_t *file_delivery_attempts,
                                   cfl_sds_t *file_path,
                                   cfl_sds_t *destination,
                                   cfl_sds_t *remote_file_id,
                                   cfl_sds_t *tag,
                                   int *part_count)
{
    cfl_sds_t     local_remote_file_id;
    char         *tmp_remote_file_id;
    cfl_sds_t     local_destination;
    char         *tmp_destination;
    int           inner_result;
    sqlite3_stmt *statement;
    cfl_sds_t     local_tag;
    cfl_sds_t     tmp_tag;
    int           result;
    cfl_sds_t     path;
    char         *tmp;

    local_remote_file_id = NULL;
    tmp_remote_file_id = NULL;
    local_destination = NULL;
    tmp_destination = NULL;
    local_tag = NULL;
    tmp_tag = NULL;
    path = NULL;

    tmp_destination = NULL;
    tmp = NULL;

    statement = context->stmt_get_next_file_part;

    flb_sqldb_lock(context->db);

    *file_path = NULL;

    result = sqlite3_step(statement);

    if (result == SQLITE_ROW) {
        *id = sqlite3_column_int64(statement, 0);
        *file_id = sqlite3_column_int64(statement, 1);
        *part_id = sqlite3_column_int64(statement, 2);
        *offset_start = sqlite3_column_int64(statement, 3);
        *offset_end = sqlite3_column_int64(statement, 4);
        *part_delivery_attempts = sqlite3_column_int64(statement, 5);
        tmp = (char *) sqlite3_column_text(statement, 6);
        *file_delivery_attempts = sqlite3_column_int64(statement, 7);
        tmp_destination = (char *) sqlite3_column_text(statement, 9);
        tmp_remote_file_id = (char *) sqlite3_column_text(statement, 10);
        tmp_tag = (char *) sqlite3_column_text(statement, 11);

        path = cfl_sds_create(tmp);
        local_tag = cfl_sds_create(tmp_tag);
        local_destination = cfl_sds_create(tmp_destination);
        local_remote_file_id = cfl_sds_create(tmp_remote_file_id);

        *part_count = flb_blob_db_file_fetch_part_count(context, *file_id);
    }
    else if (result == SQLITE_DONE) {
        /* no records */
        result = 0;
    }
    else {
        context->last_error = result;

        result = -1;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    inner_result = -1;

    if (result == SQLITE_ROW) {
        if (path == NULL ||
            local_tag == NULL ||
            local_destination == NULL ||
            local_remote_file_id == NULL) {
            result = FLB_BLOB_DB_ERROR_ALLOCATOR_FAILURE;
        }
        else{
            inner_result = flb_blob_db_file_part_in_progress(context, 1, *id);

            if (inner_result == FLB_BLOB_DB_SUCCESS) {
                *tag = local_tag;
                *file_path = path;
                *destination = local_destination;
                *remote_file_id = local_remote_file_id;
            }
        }
    }

    if (inner_result != FLB_BLOB_DB_SUCCESS ||
        result != SQLITE_ROW) {
        if (path != NULL) {
            cfl_sds_destroy(path);
        }

        if (local_tag != NULL) {
            cfl_sds_destroy(local_tag);
        }

        if (local_destination != NULL) {
            cfl_sds_destroy(local_destination);
        }

        if (local_remote_file_id != NULL) {
            cfl_sds_destroy(local_remote_file_id);
        }
    }

    return result;
}

int flb_blob_db_file_part_update_remote_id(struct flb_blob_db *context,
                                           uint64_t id,
                                           cfl_sds_t remote_id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_update_file_part_remote_id;

    flb_sqldb_lock(context->db);

    sqlite3_bind_text(statement, 1, remote_id, -1, 0);
    sqlite3_bind_int64(statement, 2, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_PART_REMOTE_ID_UPDATE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_part_uploaded(struct flb_blob_db *context,
                                   uint64_t id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_update_file_part_uploaded;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, id);

    result = sqlite3_step(statement);

    if (result != SQLITE_DONE) {
        context->last_error = result;

        result = FLB_BLOB_DB_ERROR_PART_UPLOAD_STATE_UPDATE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_part_update_delivery_attempt_counter(
        struct flb_blob_db *context,
        uint64_t file_id,
        uint64_t part_id,
        uint64_t attempts)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_update_file_part_delivery_attempt_count;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, attempts);
    sqlite3_bind_int64(statement, 2, file_id);
    sqlite3_bind_int64(statement, 3, part_id);

    result = sqlite3_step(statement);

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    if (result != SQLITE_DONE) {
        result = FLB_BLOB_DB_ERROR_PART_DELIVERY_ATTEMPT_COUNTER_UPDATE;
    }
    else {
        result = FLB_BLOB_DB_SUCCESS;

    }

    return result;
}

int flb_blob_db_file_fetch_oldest_ready(struct flb_blob_db *context,
                                        uint64_t *file_id,
                                        cfl_sds_t *path,
                                        cfl_sds_t *part_ids,
                                        cfl_sds_t *source,
                                        cfl_sds_t *file_remote_id,
                                        cfl_sds_t *file_tag,
                                        int *part_count)
{
    sqlite3_stmt *statement;
    int           result;
    int           ret;
    char         *tmp;

    tmp = NULL;
    *path = NULL;
    *part_ids = NULL;
    *source = NULL;
    *file_remote_id = NULL;
    *file_tag = NULL;

    statement = context->stmt_get_oldest_file_with_parts;

    flb_sqldb_lock(context->db);

    ret = sqlite3_step(statement);

    if (ret == SQLITE_ROW) {
        /* file_id */
        *file_id = sqlite3_column_int64(statement, 0);

        /* path */
        tmp = (char *) sqlite3_column_text(statement, 1);
        *path = cfl_sds_create(tmp);

        /* part_ids */
        tmp = (char *) sqlite3_column_text(statement, 2);
        *part_ids = cfl_sds_create(tmp);

        /* source */
        tmp = (char *) sqlite3_column_text(statement, 3);
        *source = cfl_sds_create(tmp);

        tmp = (char *) sqlite3_column_text(statement, 4);
        *file_remote_id = cfl_sds_create(tmp);

        tmp = (char *) sqlite3_column_text(statement, 5);
        *file_tag = cfl_sds_create(tmp);

        if (*path == NULL ||
            *part_ids == NULL ||
            *source == NULL ||
            *file_remote_id == NULL ||
            *file_tag == NULL) {
            result = -1;
        }
        else{
            *part_count = flb_blob_db_file_fetch_part_count(context, *file_id);

            if (*part_count <= 0) {
                result = -1;
            }
            else {
                result = 1;
            }
        }
    }
    else if (ret == SQLITE_DONE) {
        /* no records */
        result = 0;
    }
    else {
        result = -1;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    if (result == -1) {
        if (*path != NULL) {
            cfl_sds_destroy(*path);

            *path = NULL;
        }

        if (*part_ids != NULL) {
            cfl_sds_destroy(*part_ids);

            *part_ids = NULL;
        }

        if (*source != NULL) {
            cfl_sds_destroy(*source);

            *source = NULL;
        }

        if (*file_remote_id != NULL) {
            cfl_sds_destroy(*file_remote_id);

            *file_remote_id = NULL;
        }

        if (*file_tag != NULL) {
            cfl_sds_destroy(*file_tag);

            *file_tag = NULL;
        }
    }

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_fetch_part_ids(struct flb_blob_db *context,
                                    uint64_t file_id,
                                    cfl_sds_t *remote_id_list,
                                    size_t remote_id_list_size,
                                    int *remote_id_count)
{
    size_t        remote_id_index;
    sqlite3_stmt *statement;
    int           result;
    char         *tmp;

    statement = context->stmt_fetch_file_part_remote_id;

    flb_sqldb_lock(context->db);

    memset(remote_id_list, 0, sizeof(cfl_sds_t) * remote_id_list_size);

    sqlite3_bind_int64(statement, 1, file_id);

    result = -1;

    for (remote_id_index = 0 ; remote_id_index < remote_id_list_size ; remote_id_index++) {
        result = sqlite3_step(statement);

        if (result == SQLITE_ROW) {
            tmp = (char *) sqlite3_column_text(statement, 0);

            remote_id_list[remote_id_index] = flb_sds_create(tmp);

            if (remote_id_list[remote_id_index] == NULL) {
                context->last_error = result;

                result = -1;

                break;
            }
        }
        else if (result == SQLITE_DONE) {
            break;
        }
        else {
            context->last_error = result;

            result = -1;

            break;
        }
    }

    if (result == -1) {
        while (remote_id_index > 0) {
            if (remote_id_list[remote_id_index] != NULL) {
                flb_sds_destroy(remote_id_list[remote_id_index]);
            }

            remote_id_index--;
        }

        if (remote_id_list[remote_id_index] != NULL) {
            flb_sds_destroy(remote_id_list[remote_id_index]);
        }

        memset(remote_id_list, 0, sizeof(cfl_sds_t) * remote_id_list_size);
    }
    else {
        *remote_id_count = (int) remote_id_index;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

int flb_blob_db_file_fetch_part_count(struct flb_blob_db *context,
                                      uint64_t file_id)
{
    sqlite3_stmt *statement;
    int           result;

    statement = context->stmt_get_file_part_count;

    flb_sqldb_lock(context->db);

    sqlite3_bind_int64(statement, 1, file_id);

    result = sqlite3_step(statement);

    if (result == SQLITE_ROW) {
        result = (int) sqlite3_column_int64(statement, 0);
    }
    else {
        context->last_error = result;

        result = -1;
    }

    sqlite3_clear_bindings(statement);
    sqlite3_reset(statement);

    flb_sqldb_unlock(context->db);

    return result;
}

#else

int flb_blob_db_open(struct flb_blob_db *context,
                     struct flb_config *config,
                     char *path)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_close(struct flb_blob_db *context)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_exists(struct flb_blob_db *context,
                            char *path,
                            uint64_t *id)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int64_t flb_blob_db_file_insert(struct flb_blob_db *context,
                                char *tag,
                                char *source,
                                char *destination,
                                char *path,
                                size_t size)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_delete(struct flb_blob_db *context,
                            uint64_t id)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_set_aborted_state(struct flb_blob_db *context,
                                       uint64_t id,
                                       uint64_t state)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_file_change_destination(struct flb_blob_db *context,
                                     uint64_t id,
                                     cfl_sds_t destination)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_delivery_attempts(struct flb_blob_db *context,
                                       uint64_t id,
                                       uint64_t attempts)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_get_next_aborted(struct flb_blob_db *context,
                                      uint64_t *id,
                                      uint64_t *delivery_attempts,
                                      cfl_sds_t *path,
                                      cfl_sds_t *source,
                                      cfl_sds_t *remote_id,
                                      cfl_sds_t *file_tag,
                                      int *part_count)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_get_next_stale(struct flb_blob_db *context,
                                    uint64_t *id,
                                    cfl_sds_t *path,
                                    uint64_t upload_parts_freshness_threshold,
                                    cfl_sds_t *remote_id,
                                    cfl_sds_t *tag,
                                    int *part_count)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_reset_upload_states(struct flb_blob_db *context,
                                         uint64_t id)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_part_insert(struct flb_blob_db *context,
                                 uint64_t file_id,
                                 uint64_t part_id,
                                 size_t offset_start,
                                 size_t offset_end,
                                 int64_t *out_id)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_part_in_progress(struct flb_blob_db *context,
                                      int in_progress,
                                      uint64_t id)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_part_get_next(struct flb_blob_db *context,
                                   uint64_t *id,
                                   uint64_t *file_id,
                                   uint64_t *part_id,
                                   off_t *offset_start,
                                   off_t *offset_end,
                                   uint64_t *part_delivery_attempts,
                                   uint64_t *file_delivery_attempts,
                                   cfl_sds_t *file_path,
                                   cfl_sds_t *destination,
                                   cfl_sds_t *remote_file_id,
                                   cfl_sds_t *tag)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}


int flb_blob_db_file_part_uploaded(struct flb_blob_db *context, uint64_t id)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_part_update_delivery_attempt_counter(
        struct flb_blob_db *context,
        uint64_t file_id,
        uint64_t part_id,
        uint64_t attempts)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_fetch_oldest_ready(struct flb_blob_db *context,
                                        uint64_t *file_id,
                                        cfl_sds_t *path,
                                        cfl_sds_t *part_ids,
                                        cfl_sds_t *source,
                                        cfl_sds_t *file_remote_id,
                                        cfl_sds_t *file_tag,
                                        int *part_count)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_fetch_part_ids(struct flb_blob_db *context,
                                    uint64_t file_id,
                                    cfl_sds_t *remote_id_list,
                                    size_t remote_id_list_size,
                                    int *remote_id_count)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

int flb_blob_db_file_fetch_part_count(struct flb_blob_db *context,
                                      uint64_t file_id)
{
    return FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE;
}

#endif