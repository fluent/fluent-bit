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

#ifndef FLB_TAIL_SQL_H
#define FLB_TAIL_SQL_H

/*
 * In Fluent Bit we try to have a common convention for table names,
 * if the table belong to an input/output plugin, use plugin name
 * plus to what it's about, e.g:
 *
 * in_tail plugin table to track files: in_tail_files
 */
#define SQL_CREATE_FILES                                                \
    "CREATE TABLE IF NOT EXISTS in_tail_files ("                        \
    "  id      INTEGER PRIMARY KEY,"                                    \
    "  name    TEXT NOT NULL,"                                          \
    "  offset  INTEGER,"                                                \
    "  inode   INTEGER,"                                                \
    "  created INTEGER,"                                                \
    "  rotated INTEGER DEFAULT 0"                                       \
    ");"

#define SQL_GET_FILE                                                    \
    "SELECT * from in_tail_files WHERE inode=@inode order by id desc;"

#define SQL_INSERT_FILE                                             \
    "INSERT INTO in_tail_files (name, offset, inode, created)"      \
    "  VALUES (@name, @offset, @inode, @created);"

#define SQL_ROTATE_FILE                                                 \
    "UPDATE in_tail_files set name=@name,rotated=1 WHERE id=@id;"

#define SQL_UPDATE_OFFSET                                   \
    "UPDATE in_tail_files set offset=@offset WHERE id=@id;"

#define SQL_DELETE_FILE                                                 \
    "DELETE FROM in_tail_files WHERE id=@id;"

#define SQL_STMT_START_PARAM "(?"
#define SQL_STMT_START_PARAM_LEN (sizeof(SQL_STMT_START_PARAM) - 1)

#define SQL_STMT_ADD_PARAM ",?"
#define SQL_STMT_ADD_PARAM_LEN (sizeof(SQL_STMT_ADD_PARAM) - 1)

#define SQL_STMT_PARAM_END ")"
#define SQL_STMT_PARAM_END_LEN (sizeof(SQL_STMT_PARAM_END) - 1)

#define SQL_STMT_END ";"
#define SQL_STMT_END_LEN (sizeof(SQL_STMT_END) - 1)

#define SQL_DELETE_STALE_FILE_START                                     \
    "DELETE FROM in_tail_files "
#define SQL_DELETE_STALE_FILE_START_LEN                                 \
    (sizeof(SQL_DELETE_STALE_FILE_START) - 1)

#define SQL_DELETE_STALE_FILE_WHERE                                     \
    "WHERE inode NOT IN "
#define SQL_DELETE_STALE_FILE_WHERE_LEN                                 \
    (sizeof(SQL_DELETE_STALE_FILE_WHERE) - 1)

#define SQL_PRAGMA_SYNC                         \
    "PRAGMA synchronous=%i;"

#define SQL_PRAGMA_JOURNAL_MODE                 \
    "PRAGMA journal_mode=%s;"

#define SQL_PRAGMA_LOCKING_MODE                 \
    "PRAGMA locking_mode=EXCLUSIVE;"

#endif
