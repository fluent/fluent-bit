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

#ifndef FLB_KUBERNETES_EVENTS_SQL_H
#define FLB_KUBERNETES_EVENTS_SQL_H

/*
 * In Fluent Bit we try to have a common convention for table names,
 * if the table belongs to an input/output plugin, use the plugins name
 * with the name of the object or type.
 *
 * in_kubernetes_events plugin table to track kubernetes events: 
 *         in_kubernetes_events
 */
#define SQL_CREATE_KUBERNETES_EVENTS                                    \
    "CREATE TABLE IF NOT EXISTS in_kubernetes_events ("                 \
    "  id              INTEGER PRIMARY KEY,"                            \
    "  uid             TEXT NOT NULL,"                                  \
    "  resourceVersion INTEGER NOT NULL,"                               \
    "  created         INTEGER NOT NULL"                                \
    ");"

#define SQL_KUBERNETES_EVENT_EXISTS_BY_UID                              \
    "SELECT COUNT(id) "                                                 \
    "    FROM in_kubernetes_events "                                    \
    "    WHERE uid=@uid;"

#define SQL_INSERT_KUBERNETES_EVENTS                                    \
    "INSERT INTO in_kubernetes_events (uid, resourceVersion, created)"  \
    "  VALUES (@uid, @resourceVersion, @created);"

#define SQL_DELETE_OLD_KUBERNETES_EVENTS                                \
    "DELETE FROM in_kubernetes_events WHERE created <= @createdBefore;"

#define SQL_PRAGMA_SYNC                         \
    "PRAGMA synchronous=%i;"

#define SQL_PRAGMA_JOURNAL_MODE                 \
    "PRAGMA journal_mode=%s;"

#define SQL_PRAGMA_LOCKING_MODE                 \
    "PRAGMA locking_mode=EXCLUSIVE;"

#endif
