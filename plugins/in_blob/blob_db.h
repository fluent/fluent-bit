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

#ifndef IN_BLOB_DB_H
#define IN_BLOB_DB_H

#define SQL_CREATE_BLOB_FILES                                            \
    "CREATE TABLE IF NOT EXISTS in_blob_files ("                         \
    "  id        INTEGER PRIMARY KEY,"                                   \
    "  path      TEXT NOT NULL,"                                         \
    "  size      INTEGER,"                                               \
    "  created   INTEGER"                                                \
    ");"

#define SQL_INSERT_FILE                                                  \
    "INSERT INTO in_blob_files (path, size, created)"                    \
    "  VALUES (@path, @size, @created);"

#define SQL_DELETE_FILE                                                  \
    "DELETE FROM in_blob_files WHERE id=@id;"

#define SQL_GET_FILE                                                    \
    "SELECT * from in_blob_files WHERE path=@path order by id desc;"

struct flb_sqldb *blob_db_open(struct blob_ctx *ctx, char *db_path);
int blob_db_close(struct blob_ctx *ctx);
int blob_db_file_exists(struct blob_ctx *ctx, char *path, uint64_t *id);
int64_t blob_db_file_insert(struct blob_ctx *ctx, char *path, size_t size);
int blob_db_file_delete(struct blob_ctx *ctx, uint64_t id, char *path);

#endif