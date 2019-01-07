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

#ifndef FLB_SYSTEMD_DB_H
#define FLB_SYSTEMD_DB_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>

#include "systemd_config.h"

#define SQL_CREATE_CURSOR                                               \
    "CREATE TABLE IF NOT EXISTS in_systemd_cursor ("                    \
    "  cursor  TEXT NOT NULL,"                                          \
    "  updated INTEGER"                                                 \
    ");"

#define SQL_GET_CURSOR \
    "SELECT * FROM in_systemd_cursor;"

#define SQL_INSERT_CURSOR                               \
    "INSERT INTO in_systemd_cursor (cursor, updated)"   \
    "  VALUES ('%s', %lu);"

#define SQL_UPDATE_CURSOR \
    "UPDATE in_systemd_cursor SET cursor='%s', updated=%lu;"

struct flb_sqldb *flb_systemd_db_open(char *path, struct flb_input_instance *in,
                                      struct flb_config *config);
int flb_systemd_db_close(struct flb_sqldb *db);
int flb_systemd_db_set_cursor(struct flb_systemd_config *ctx, char *cursor);
char *flb_systemd_db_get_cursor(struct flb_systemd_config *ctx);

#endif
