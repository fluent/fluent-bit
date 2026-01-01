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

#ifndef OUT_AZURE_BLOB_DB_H
#define OUT_AZURE_BLOB_DB_H

#include <fluent-bit/flb_output_plugin.h>
#include "azure_blob.h"

#define SQL_PRAGMA_FOREIGN_KEYS "PRAGMA foreign_keys = ON;"

#define SQL_CREATE_AZURE_BLOB_FILES                                       \
    "CREATE TABLE IF NOT EXISTS out_azure_blob_files ("                   \
    "  id                    INTEGER PRIMARY KEY,"                        \
    "  source                TEXT NOT NULL,"                              \
    "  destination           TEXT NOT NULL,"                              \
    "  path                  TEXT NOT NULL,"                              \
    "  size                  INTEGER,"                                    \
    "  created               INTEGER,"                                    \
    "  delivery_attempts     INTEGER DEFAULT 0,"                          \
    "  aborted               INTEGER DEFAULT 0,"                          \
    "  last_delivery_attempt INTEGER DEFAULT 0"                           \
    ");"

#define SQL_CREATE_AZURE_BLOB_PARTS                                       \
    "CREATE TABLE IF NOT EXISTS out_azure_blob_parts ("                   \
    "  id                INTEGER PRIMARY KEY,"                            \
    "  file_id           INTEGER NOT NULL,"                               \
    "  part_id           INTEGER NOT NULL,"                               \
    "  uploaded          INTEGER DEFAULT 0,"                              \
    "  in_progress       INTEGER DEFAULT 0,"                              \
    "  offset_start      INTEGER,"                                        \
    "  offset_end        INTEGER,"                                        \
    "  delivery_attempts INTEGER DEFAULT 0,"                              \
    "  FOREIGN KEY (file_id) REFERENCES out_azure_blob_files(id) "        \
    "    ON DELETE CASCADE"                                               \
    ");"

#define SQL_INSERT_FILE                                              \
    "INSERT INTO out_azure_blob_files (source, destination, path, size, created)" \
    "  VALUES (@source, @destination, @path, @size, @created);"

/* DELETE a registered file and all it parts */
#define SQL_DELETE_FILE                                              \
    "DELETE FROM out_azure_blob_files WHERE id=@id;"

#define SQL_SET_FILE_ABORTED_STATE                                    \
    "UPDATE out_azure_blob_files SET aborted=@state WHERE id=@id;"

#define SQL_UPDATE_FILE_DESTINATION                                   \
    "UPDATE out_azure_blob_files SET destination=@destination WHERE id=@id;"

#define SQL_UPDATE_FILE_DELIVERY_ATTEMPT_COUNT                        \
    "UPDATE out_azure_blob_files " \
    "   SET delivery_attempts=@delivery_attempts, " \
    "       last_delivery_attempt=UNIXEPOCH() " \
    " WHERE id=@id;"

#define SQL_GET_FILE                                                 \
    "SELECT * FROM out_azure_blob_files WHERE path=@path ORDER BY id DESC;"

#define SQL_GET_NEXT_ABORTED_FILE                                    \
    "SELECT id, azbf.delivery_attempts, source, path "               \
    "  FROM out_azure_blob_files azbf "                              \
    " WHERE aborted = 1 "                                            \
    "   AND (SELECT COUNT(*) "                                       \
    "          FROM out_azure_blob_parts azbp "                      \
    "         WHERE azbp.file_id = azbf.id "                         \
    "           AND in_progress = 1) = 0 "                           \
    "ORDER BY id DESC "                                              \
    "LIMIT 1;"


#define SQL_GET_NEXT_STALE_FILE                                    \
    "SELECT id, path "                                             \
    "  FROM out_azure_blob_files azbf "                            \
    " WHERE aborted = 0 "                                          \
    "   AND last_delivery_attempt > 0 "                            \
    "   AND last_delivery_attempt < @freshness_threshold "         \
    "ORDER BY id DESC "                                            \
    "LIMIT 1;"

#define SQL_INSERT_FILE_PART                                                   \
    "INSERT INTO out_azure_blob_parts (file_id, part_id, offset_start, offset_end)" \
    "  VALUES (@file_id, @part_id, @offset_start, @offset_end);"

#define SQL_UPDATE_FILE_PART_UPLOADED                                     \
    "UPDATE out_azure_blob_parts SET uploaded=1, in_progress=0 WHERE id=@id;"

#define SQL_UPDATE_FILE_PART_IN_PROGRESS                                   \
    "UPDATE out_azure_blob_parts SET in_progress=@status WHERE id=@id;"

#define SQL_UPDATE_FILE_PART_DELIVERY_ATTEMPT_COUNT                        \
    "UPDATE out_azure_blob_parts "                                         \
    "   SET delivery_attempts=@delivery_attempts "                         \
    " WHERE file_id=@file_id "                                             \
    "   AND part_id=@part_id;"

#define SQL_RESET_FILE_UPLOAD_STATES                                       \
    "UPDATE out_azure_blob_files "                                         \
    "   SET last_delivery_attempt=0 "                                      \
    " WHERE id=@id;"

#define SQL_RESET_FILE_PART_UPLOAD_STATES                                  \
    "UPDATE out_azure_blob_parts "                                         \
    "   SET delivery_attempts=0, "                                         \
    "       uploaded=0, "                                                  \
    "       in_progress=0 "                                                \
    " WHERE file_id=@id;"

/* Find the oldest files and retrieve the oldest part ready to be uploaded */
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
    "         f.destination "                          \
    "    FROM out_azure_blob_parts p "                 \
    "    JOIN out_azure_blob_files f "                 \
    "      ON p.file_id = f.id "                       \
    "   WHERE p.uploaded = 0 "                         \
    "     AND p.in_progress = 0 "                      \
    "     AND f.aborted = 0 "                          \
    "     AND (p.part_id = 0 OR "                      \
    "          (SELECT sp.uploaded "                   \
    "             FROM out_azure_blob_parts sp "       \
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
#define SQL_GET_OLDEST_FILE_WITH_PARTS_CONCAT                                        \
    "SELECT f.id, f.path, GROUP_CONCAT(p.part_id ORDER BY p.part_id ASC) AS part_ids, f.source " \
    "FROM out_azure_blob_files f "                                               \
    "JOIN out_azure_blob_parts p ON f.id = p.file_id "                           \
    "WHERE p.uploaded = 1 " \
    "GROUP BY f.id "        \
    "HAVING COUNT(p.id) = (SELECT COUNT(p2.id) FROM out_azure_blob_parts p2 WHERE p2.file_id = f.id) " \
    "ORDER BY f.created ASC " \
    "LIMIT 1;"

struct flb_sqldb *azb_db_open(struct flb_azure_blob *ctx, char *db_path);
int azb_db_close(struct flb_azure_blob *ctx);
int azb_db_file_exists(struct flb_azure_blob *ctx, char *path, uint64_t *id);

int64_t azb_db_file_insert(struct flb_azure_blob *ctx,
                           char *source,
                           char *destination,
                           char *path,
                           size_t size);

int azb_db_file_delete(struct flb_azure_blob *ctx, uint64_t id, char *path);

int azb_db_file_set_aborted_state(struct flb_azure_blob *ctx,
                                  uint64_t id, char *path,
                                  uint64_t state);

int azb_db_file_change_destination(struct flb_azure_blob *ctx, uint64_t id, cfl_sds_t destination);

int azb_db_file_delivery_attempts(struct flb_azure_blob *ctx, uint64_t id, uint64_t attempts);

int azb_db_file_get_next_aborted(struct flb_azure_blob *ctx,
                                 uint64_t *id,
                                 uint64_t *delivery_attempts,
                                 cfl_sds_t *path,
                                 cfl_sds_t *source);


int azb_db_file_get_next_stale(struct flb_azure_blob *ctx,
                               uint64_t *id,
                               cfl_sds_t *path);

int azb_db_file_reset_upload_states(struct flb_azure_blob *ctx, uint64_t id, char *path);

int azb_db_file_part_insert(struct flb_azure_blob *ctx, uint64_t file_id,
                            uint64_t part_id,
                            size_t offset_start, size_t offset_end,
                            int64_t *out_id);
int azb_db_file_part_in_progress(struct flb_azure_blob *ctx, int in_progress, uint64_t id);
int azb_db_file_part_get_next(struct flb_azure_blob *ctx,
                              uint64_t *id, uint64_t *file_id, uint64_t *part_id,
                              off_t *offset_start, off_t *offset_end,
                              uint64_t *part_delivery_attempts,
                              uint64_t *file_delivery_attempts,
                              cfl_sds_t *file_path,
                              cfl_sds_t *destination);
int azb_db_file_part_uploaded(struct flb_azure_blob *ctx, uint64_t id);
int azb_db_file_part_delivery_attempts(struct flb_azure_blob *ctx,
                                       uint64_t file_id,
                                       uint64_t part_id,
                                       uint64_t attempts);

int azb_db_file_oldest_ready(struct flb_azure_blob *ctx,
                             uint64_t *file_id, cfl_sds_t *path, cfl_sds_t *part_ids, cfl_sds_t *source);
#endif