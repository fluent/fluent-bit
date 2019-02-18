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

#ifndef FLB_SP_PARSER_H
#define FLB_SP_PARSER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/stream_processor/flb_sp.h>

/* Aggregation functions */
#define FLB_SP_AVG       1
#define FLB_SP_SUM       2
#define FLB_SP_COUNT     3
#define FLB_SP_MIN       4
#define FLB_SP_MAX       5

/* Source type */
#define FLB_SP_STREAM    0
#define FLB_SP_TAG       1

/* Key selection */
struct flb_sp_cmd_key {
    int aggr_func;            /* Aggregation function */
    flb_sds_t name;           /* Key name */
    flb_sds_t alias;          /* Key output alias */
    struct mk_list _head;     /* Link to flb_sp_cmd->keys */
};

struct flb_sp_cmd {
    struct mk_list keys;      /* head of record fields */
    int source_type;          /* STREAM or TAG */
    char *source_name;
};

struct flb_sp_cmd *flb_sp_cmd_create(char *sql);
void flb_sp_cmd_destroy(struct flb_sp_cmd *cmd);

int flb_sp_cmd_key_add(struct flb_sp_cmd *cmd, int aggr,
                       char *key_name, char *key_alias);
void flb_sp_cmd_key_del(struct flb_sp_cmd_key *key);
int flb_sp_cmd_source(struct flb_sp_cmd *cmd, int type, char *source);
void flb_sp_cmd_dump(struct flb_sp_cmd *cmd);

#endif
