/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#define SQL_GET_FILE "SELECT * from in_tail_files WHERE name='%s'"  \
    " AND inode=%"PRIu64";"

#define SQL_INSERT_FILE                                             \
    "INSERT INTO in_tail_files (name, offset, inode, created)"      \
    "  VALUES ('%s', %lu, %lu, %lu);"

#define SQL_UPDATE_OFFSET                               \
    "UPDATE in_tail_files set offset=%lu WHERE id=%"PRId64";"

#define SQL_ROTATE_FILE                         \
    "UPDATE in_tail_files set name='%s',rotated=1 WHERE id=%"PRId64";"

#define SQL_PRAGMA_SYNC                         \
    "PRAGMA synchronous=%i;"
#endif
