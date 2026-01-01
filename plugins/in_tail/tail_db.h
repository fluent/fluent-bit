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

#ifndef FLB_TAIL_DB_H
#define FLB_TAIL_DB_H

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_sqldb.h>

#include "tail_file.h"

struct flb_sqldb *flb_tail_db_open(const char *path,
                                   struct flb_input_instance *in,
                                   struct flb_tail_config *ctx,
                                   struct flb_config *config);

int flb_tail_db_close(struct flb_sqldb *db);
int flb_tail_db_file_set(struct flb_tail_file *file,
                         struct flb_tail_config *ctx);
int flb_tail_db_file_offset(struct flb_tail_file *file,
                            struct flb_tail_config *ctx);
int flb_tail_db_file_rotate(const char *new_name,
                            struct flb_tail_file *file,
                            struct flb_tail_config *ctx);
int flb_tail_db_file_delete(struct flb_tail_file *file,
                            struct flb_tail_config *ctx);
int flb_tail_db_stale_file_delete(struct flb_input_instance *ins,
                                  struct flb_config *config,
                                  struct flb_tail_config *ctx);
#endif
