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

#ifndef FLB_BLOB_DB_H
#define FLB_BLOB_DB_H

#include <fluent-bit/flb_lock.h>

#define SQL_PRAGMA_FOREIGN_KEYS "PRAGMA foreign_keys = ON;"

#define SQL_CREATE_BLOB_FILES                                             \
    "CREATE TABLE IF NOT EXISTS blob_files ("                             \
    "  id                    INTEGER PRIMARY KEY,"                        \
    "  tag                   TEXT NOT NULL DEFAULT '',"                   \
    "  source                TEXT NOT NULL,"                              \
    "  destination           TEXT NOT NULL,"                              \
    "  path                  TEXT NOT NULL,"                              \
    "  remote_id             TEXT NOT NULL DEFAULT '',"                   \
    "  size                  INTEGER,"                                    \
    "  created               INTEGER,"                                    \
    "  delivery_attempts     INTEGER DEFAULT 0,"                          \
    "  aborted               INTEGER DEFAULT 0,"                          \
    "  last_delivery_attempt INTEGER DEFAULT 0"                           \
    ");"

#define SQL_CREATE_BLOB_PARTS                                             \
    "CREATE TABLE IF NOT EXISTS blob_parts ("                             \
    "  id                INTEGER PRIMARY KEY,"                            \
    "  file_id           INTEGER NOT NULL,"                               \
    "  part_id           INTEGER NOT NULL,"                               \
    "  remote_id         TEXT NOT NULL DEFAULT '',"                       \
    "  uploaded          INTEGER DEFAULT 0,"                              \
    "  in_progress       INTEGER DEFAULT 0,"                              \
    "  offset_start      INTEGER,"                                        \
    "  offset_end        INTEGER,"                                        \
    "  delivery_attempts INTEGER DEFAULT 0,"                              \
    "  FOREIGN KEY (file_id) REFERENCES blob_files(id) "                  \
    "    ON DELETE CASCADE"                                               \
    ");"

#define SQL_INSERT_FILE                                                   \
    "INSERT INTO blob_files (tag, source, destination, path, size, created)"   \
    "  VALUES (@tag, @source, @destination, @path, @size, @created);"

#define SQL_DELETE_FILE                                                   \
    "DELETE FROM blob_files WHERE id=@id;"

#define SQL_SET_FILE_ABORTED_STATE                                        \
    "UPDATE blob_files SET aborted=@state WHERE id=@id;"

#define SQL_UPDATE_FILE_REMOTE_ID                                         \
    "UPDATE blob_files SET remote_id=@remote_id WHERE id=@id;"

#define SQL_UPDATE_FILE_DESTINATION                                       \
    "UPDATE blob_files SET destination=@destination WHERE id=@id;"

#define SQL_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT                            \
    "UPDATE blob_files "                                                  \
    "   SET delivery_attempts=@delivery_attempts, "                       \
    "       last_delivery_attempt=UNIXEPOCH() "                           \
    " WHERE id=@id;"

#define SQL_GET_FILE                                                      \
    "SELECT * FROM blob_files WHERE path=@path ORDER BY id DESC;"

#define SQL_GET_FILE_PART_COUNT                                           \
    "SELECT count(id) "                                                   \
    "  FROM blob_parts "                                                  \
    " WHERE file_id=@id;"

#define SQL_GET_NEXT_ABORTED_FILE                                    \
    "SELECT id, bf.delivery_attempts, source, path, remote_id, "     \
    "       tag "                                                    \
    "  FROM blob_files bf "                                          \
    " WHERE aborted = 1 "                                            \
    "   AND (SELECT COUNT(*) "                                       \
    "          FROM blob_parts bp "                                  \
    "         WHERE bp.file_id = bf.id "                             \
    "           AND in_progress = 1) = 0 "                           \
    "ORDER BY id DESC "                                              \
    "LIMIT 1;"

#define SQL_GET_NEXT_STALE_FILE                                    \
    "SELECT id, path, remote_id, tag "                             \
    "  FROM blob_files "                                           \
    " WHERE aborted = 0 "                                          \
    "   AND last_delivery_attempt > 0 "                            \
    "   AND last_delivery_attempt < @freshness_threshold "         \
    "ORDER BY id DESC "                                            \
    "LIMIT 1;"

#define SQL_INSERT_FILE_PART                                              \
    "INSERT INTO blob_parts (file_id, part_id, offset_start, offset_end)" \
    "  VALUES (@file_id, @part_id, @offset_start, @offset_end);"

#define SQL_UPDATE_FILE_PART_REMOTE_ID                                    \
    "UPDATE blob_parts SET remote_id=@remote_id WHERE id=@id;"

#define SQL_GET_FILE_PART_REMOTE_ID                                       \
    "SELECT remote_id "                                                   \
    "  FROM blob_parts "                                                  \
    " WHERE file_id=@id;"

#define SQL_UPDATE_FILE_PART_UPLOADED                                     \
    "UPDATE blob_parts SET uploaded=1, in_progress=0 WHERE id=@id;"

#define SQL_UPDATE_FILE_PART_IN_PROGRESS                                  \
    "UPDATE blob_parts SET in_progress=@status WHERE id=@id;"

#define SQL_UPDATE_FILE_PART_DELIVERY_ATTEMPT_COUNT                        \
    "UPDATE blob_parts "                                                   \
    "   SET delivery_attempts=@delivery_attempts "                         \
    " WHERE file_id=@file_id "                                             \
    "   AND part_id=@part_id;"

#define SQL_RESET_FILE_UPLOAD_STATES                                       \
    "UPDATE blob_files "                                                   \
    "   SET last_delivery_attempt=0 "                                      \
    " WHERE id=@id;"

#define SQL_RESET_FILE_PART_UPLOAD_STATES                                  \
    "UPDATE blob_parts "                                                   \
    "   SET delivery_attempts=0, "                                         \
    "       uploaded=0, "                                                  \
    "       in_progress=0 "                                                \
    " WHERE file_id=@id;"

#define SQL_GET_NEXT_FILE_PART                         \
    "  SELECT p.id, "                                  \
    "         p.file_id, "                             \
    "         p.part_id, "                             \
    "         p.offset_start, "                        \
    "         p.offset_end, "                          \
    "         p.delivery_attempts, "                   \
    "         f.path, "                                \
    "         f.delivery_attempts, "                   \
    "         f.last_delivery_attempt, "               \
    "         f.destination, "                         \
    "         f.remote_id, "                           \
    "         f.tag "                                  \
    "    FROM blob_parts p "                           \
    "    JOIN blob_files f "                           \
    "      ON p.file_id = f.id "                       \
    "   WHERE p.uploaded = 0 "                         \
    "     AND p.in_progress = 0 "                      \
    "     AND f.aborted = 0 "                          \
    "     AND (p.part_id = 0 OR "                      \
    "          (SELECT sp.uploaded "                   \
    "             FROM blob_parts sp "                 \
    "            WHERE sp.part_id = 0 "                \
    "              AND sp.file_id = p.file_id) = 1) "  \
    "ORDER BY f.created ASC, "                         \
    "         p.part_id ASC "                          \
    "   LIMIT 1;"


/*
 * Query to retrieve the oldest file which all it parts are mark as uploaded, this
 * query will group the results in a single record, e.g:
 *
*  path              part_ids
 *  ----------------  ----------  ------------------------------------------------------------
 *  /.../alice29.txt  1726423769  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
 *                                19,20,21,22,23,24,25,26,27,28,29,30
 *
 * this query is used to compose
 */
#define SQL_GET_OLDEST_FILE_WITH_PARTS_CONCAT                                                     \
    "SELECT f.id, f.path, GROUP_CONCAT(p.part_id ORDER BY p.part_id ASC) AS part_ids, f.source, " \
    "       f.remote_id, f.tag "                                                                  \
    "FROM blob_files f "                                                                          \
    "JOIN blob_parts p ON f.id = p.file_id "                                                      \
    "WHERE p.uploaded = 1 "                                                                       \
    "GROUP BY f.id "                                                                              \
    "HAVING COUNT(p.id) = (SELECT COUNT(p2.id) FROM blob_parts p2 WHERE p2.file_id = f.id) "      \
    "ORDER BY f.created ASC "                                                                     \
    "LIMIT 1;"


#define FLB_BLOB_DB_SUCCESS                         0
#define FLB_BLOB_DB_ERROR_NO_BACKEND_AVAILABLE     -1
#define FLB_BLOB_DB_ERROR_ALLOCATOR_FAILURE        -2
#define FLB_BLOB_DB_ERROR_INVALID_BLOB_DB_CONTEXT  -3
#define FLB_BLOB_DB_ERROR_INVALID_FLB_CONTEXT      -4
#define FLB_BLOB_DB_ERROR_INVALID_DATABASE_PATH    -5
#define FLB_BLOB_DB_ERROR_SQLDB_OPEN_FAILURE       -6
#define FLB_BLOB_DB_ERROR_FILE_TABLE_CREATION      -7
#define FLB_BLOB_DB_ERROR_PART_TABLE_CREATION      -8
#define FLB_BLOB_DB_ERROR_SQLDB_FK_INIT_FAILURE    -9
#define FLB_BLOB_DB_ERROR_LOCK_INIT                -10

#define FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE    -200

#define FLB_BLOB_DB_ERROR_FILE_INSERT                          \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -1
#define FLB_BLOB_DB_ERROR_FILE_DELETE                          \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -2
#define FLB_BLOB_DB_ERROR_FILE_ABORT                           \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -3
#define FLB_BLOB_DB_ERROR_FILE_DESTINATION_CHANGE              \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -4
#define FLB_BLOB_DB_ERROR_FILE_REMOTE_ID_UPDATE                \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -5
#define FLB_BLOB_DB_ERROR_FILE_DELIVERY_ATTEMPT_UPDATE         \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -6
#define FLB_BLOB_DB_ERROR_PART_UPLOAD_STATE_RESET              \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -7
#define FLB_BLOB_DB_ERROR_FILE_UPLOAD_STATE_RESET              \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -8
#define FLB_BLOB_DB_ERROR_FILE_PART_INSERT                     \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -9
#define FLB_BLOB_DB_ERROR_FILE_PART_IN_PROGRESS_UPDATE         \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -10
#define FLB_BLOB_DB_ERROR_PART_UPLOAD_STATE_UPDATE             \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -11
#define FLB_BLOB_DB_ERROR_PART_DELIVERY_ATTEMPT_COUNTER_UPDATE \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -12
#define FLB_BLOB_DB_ERROR_PART_REMOTE_ID_UPDATE                \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -13
#define FLB_BLOB_DB_ERROR_PART_REMOTE_ID_FETCH                 \
    FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_BASE -14

#define FLB_BLOB_DB_ERROR_EXECUTING_STATEMENT_TOP              \
    FLB_BLOB_DB_ERROR_PART_REMOTE_ID_UPDATE

/* These errors are highly speciifc and thus client code should be able to
 * range check them.
 */

#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE -100

#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_INSERT_FILE                             \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 0
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_DELETE_FILE                             \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 1
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_ABORT_FILE                              \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 2
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_FILE                                \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 3
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_DESTINATION                 \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 4
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_REMOTE_ID                   \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 5
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT      \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 6
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_SET_FILE_ABORTED_STATE                  \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 7
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_NEXT_ABORTED_FILE                   \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 8
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_NEXT_STALE_FILE                     \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 9
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_RESET_FILE_UPLOAD_STATES                \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 10
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_RESET_FILE_PART_UPLOAD_STATES           \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 11
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_INSERT_FILE_PART                        \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 12
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_PART_UPLOADED               \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 13
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_PART_REMOTE_ID              \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 14
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_FETCH_FILE_PART_REMOTE_ID               \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 15
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_PART_DELIVERY_ATTEMPT_COUNT \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 16
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_NEXT_FILE_PART                      \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 17
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_UPDATE_FILE_PART_IN_PROGRESS            \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 18
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_OLDEST_FILE_WITH_PARTS              \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 19
#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_FILE_PART_COUNT                     \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_BASE - 20

#define FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_TOP                                     \
    FLB_BLOB_DB_ERROR_PREPARING_STATEMENT_GET_OLDEST_FILE_WITH_PARTS

#ifdef FLB_HAVE_SQLDB
#include <fluent-bit/flb_sqldb.h>

typedef struct flb_sqldb __internal_flb_sqldb;
typedef sqlite3_stmt     __internal_sqlite3_stmt;
#else
typedef void __internal_flb_sqldb;
typedef void __internal_sqlite3_stmt;
#endif

struct flb_blob_db {
    /* database context */
    __internal_flb_sqldb    *db;
    int                      last_error;
    flb_lock_t               global_lock;

    /* prepared statements: files  */
    __internal_sqlite3_stmt *stmt_insert_file;
    __internal_sqlite3_stmt *stmt_delete_file;
    __internal_sqlite3_stmt *stmt_abort_file;
    __internal_sqlite3_stmt *stmt_get_file;
    __internal_sqlite3_stmt *stmt_get_file_part_count;
    __internal_sqlite3_stmt *stmt_update_file_remote_id;
    __internal_sqlite3_stmt *stmt_update_file_destination;
    __internal_sqlite3_stmt *stmt_update_file_delivery_attempt_count;
    __internal_sqlite3_stmt *stmt_set_file_aborted_state;
    __internal_sqlite3_stmt *stmt_get_next_aborted_file;
    __internal_sqlite3_stmt *stmt_get_next_stale_file;
    __internal_sqlite3_stmt *stmt_reset_file_upload_states;

    /* prepared statement: file parts */
    __internal_sqlite3_stmt *stmt_insert_file_part;
    __internal_sqlite3_stmt *stmt_fetch_file_part_remote_id;
    __internal_sqlite3_stmt *stmt_update_file_part_remote_id;
    __internal_sqlite3_stmt *stmt_update_file_part_uploaded;
    __internal_sqlite3_stmt *stmt_reset_file_part_upload_states;
    __internal_sqlite3_stmt *stmt_update_file_part_delivery_attempt_count;
    __internal_sqlite3_stmt *stmt_get_next_file_part;
    __internal_sqlite3_stmt *stmt_update_file_part_in_progress;

    __internal_sqlite3_stmt *stmt_get_oldest_file_with_parts;
};

int flb_blob_db_open(struct flb_blob_db *context,
                     struct flb_config *config,
                     char *path);

int flb_blob_db_close(struct flb_blob_db *context);

int flb_blob_db_lock(struct flb_blob_db *context);

int flb_blob_db_unlock(struct flb_blob_db *context);

int flb_blob_db_file_exists(struct flb_blob_db *context,
                            char *path,
                            uint64_t *id);

int64_t flb_blob_db_file_insert(struct flb_blob_db *context,
                                char *tag,
                                char *source,
                                char *destination,
                                char *path,
                                size_t size);

int flb_blob_db_file_delete(struct flb_blob_db *context,
                            uint64_t id,
                            char *path);

int flb_blob_db_file_set_aborted_state(struct flb_blob_db *context,
                                       uint64_t id,
                                       char *path,
                                       uint64_t state);

int flb_blob_file_change_destination(struct flb_blob_db *context,
                                     uint64_t id,
                                     cfl_sds_t destination);

int flb_blob_db_file_delivery_attempts(struct flb_blob_db *context,
                                       uint64_t id,
                                       uint64_t attempts);

int flb_blob_file_update_remote_id(struct flb_blob_db *context,
                                   uint64_t id,
                                   cfl_sds_t remote_id);

int flb_blob_db_file_get_next_aborted(struct flb_blob_db *context,
                                      uint64_t *id,
                                      uint64_t *delivery_attempts,
                                      cfl_sds_t *path,
                                      cfl_sds_t *source,
                                      cfl_sds_t *remote_id,
                                      cfl_sds_t *file_tag,
                                      int *part_count);

int flb_blob_db_file_get_next_stale(struct flb_blob_db *context,
                                    uint64_t *id,
                                    cfl_sds_t *path,
                                    uint64_t upload_parts_freshness_threshold,
                                    cfl_sds_t *remote_id,
                                    cfl_sds_t *tag,
                                    int *part_count);

int flb_blob_db_file_reset_upload_states(struct flb_blob_db *context,
                                         uint64_t id,
                                         char *path);

int flb_blob_db_file_part_insert(struct flb_blob_db *context,
                                 uint64_t file_id,
                                 uint64_t part_id,
                                 size_t offset_start,
                                 size_t offset_end,
                                 int64_t *out_id);

int flb_blob_db_file_part_in_progress(struct flb_blob_db *context,
                                      int in_progress,
                                      uint64_t id);

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
                                   int *part_count);

int flb_blob_db_file_part_update_remote_id(struct flb_blob_db *context,
                                           uint64_t id,
                                           cfl_sds_t remote_id);

int flb_blob_db_file_part_uploaded(struct flb_blob_db *context, uint64_t id);

int flb_blob_db_file_part_update_delivery_attempt_counter(
        struct flb_blob_db *context,
        uint64_t file_id,
        uint64_t part_id,
        uint64_t attempts);

int flb_blob_db_file_fetch_oldest_ready(struct flb_blob_db *context,
                                        uint64_t *file_id,
                                        cfl_sds_t *path,
                                        cfl_sds_t *part_ids,
                                        cfl_sds_t *source,
                                        cfl_sds_t *file_remote_id,
                                        cfl_sds_t *file_tag,
                                        int *part_count);

int flb_blob_db_file_fetch_part_ids(struct flb_blob_db *context,
                                    uint64_t file_id,
                                    cfl_sds_t *remote_id_list,
                                    size_t remote_id_list_size,
                                    int *remote_id_count);

int flb_blob_db_file_fetch_part_count(struct flb_blob_db *context,
                                      uint64_t file_id);
#endif