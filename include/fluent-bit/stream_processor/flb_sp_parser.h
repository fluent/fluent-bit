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

/* Date time functions */
#define FLB_SP_NOW             10
#define FLB_SP_UNIX_TIMESTAMP  11

/* Command type */
#define FLB_SP_SELECT        0
#define FLB_SP_CREATE_STREAM 1

/* Source type */
#define FLB_SP_STREAM    0
#define FLB_SP_TAG       1

/* Expression type */
#define FLB_LOGICAL_OP   0
#define FLB_EXP_KEY      1
#define FLB_EXP_BOOL     2
#define FLB_EXP_INT      3
#define FLB_EXP_FLOAT    4
#define FLB_EXP_STRING   5

/* Logical operation */
#define FLB_EXP_PAR      0

#define FLB_EXP_NOT      1
#define FLB_EXP_AND      2
#define FLB_EXP_OR       3

#define FLB_EXP_EQ       4
#define FLB_EXP_LT       5
#define FLB_EXP_LTE      6
#define FLB_EXP_GT       7
#define FLB_EXP_GTE      8


/* Property (key/value) */
struct flb_sp_cmd_prop {
    flb_sds_t key;            /* key name */
    flb_sds_t val;            /* value name */
    struct mk_list _head;     /* Link to flb_sp_cmd->stream_props */
};

/* Key selection */
struct flb_sp_cmd_key {
    int aggr_func;            /* Aggregation function */
    int time_func;            /* Time function */
    flb_sds_t name;           /* Key name */
    flb_sds_t alias;          /* Key output alias */
    struct mk_list _head;     /* Link to flb_sp_cmd->keys */
};

struct flb_sp_cmd {
    int type;                      /* FLB_SP_CREATE_STREAM or FLB_SP_SELECT */

    /* Stream creation */
    flb_sds_t stream_name;         /* Name for created stream */
    struct mk_list stream_props;   /* Stream properties: WITH(a='b',..) */

    /* Selection */
    struct mk_list keys;           /* list head of record fields */

    struct flb_exp *condition;     /* WHERE condition in select statement */

    /* Source of data */
    int source_type;               /* FLB_SP_STREAM or FLB_SP_TAG */
    flb_sds_t source_name;         /* Name after stream: or tag:  */
};

/* condition value types */
typedef union {
    bool boolean;
    int64_t i64;
    double f64;
    flb_sds_t string;
} sp_val;

struct flb_exp {
    int type;
    struct flb_exp *left;
    struct flb_exp *right;
};

struct flb_exp_op {
    int type;
    struct flb_exp *left;
    struct flb_exp *right;
    int operation;
};

struct flb_exp_key {
    int type;
    flb_sds_t name;
};

struct flb_exp_val {
    int type;
    sp_val val;
};

struct flb_sp_cmd *flb_sp_cmd_create(char *sql);
void flb_sp_cmd_destroy(struct flb_sp_cmd *cmd);

/* Stream */
int flb_sp_cmd_stream_new(struct flb_sp_cmd *cmd, char *stream_name);
int flb_sp_cmd_stream_prop_add(struct flb_sp_cmd *cmd, char *key, char *val);
void flb_sp_cmd_stream_prop_del(struct flb_sp_cmd_prop *prop);
char *flb_sp_cmd_stream_prop_get(struct flb_sp_cmd *cmd, char *key);

/* Selection keys */
int flb_sp_cmd_key_add(struct flb_sp_cmd *cmd, int func,
                       char *key_name, char *key_alias);
void flb_sp_cmd_key_del(struct flb_sp_cmd_key *key);
int flb_sp_cmd_source(struct flb_sp_cmd *cmd, int type, char *source);
void flb_sp_cmd_dump(struct flb_sp_cmd *cmd);

void flb_sp_cmd_condition_add(struct flb_sp_cmd *cmd, struct flb_exp *e);
struct flb_exp *flb_sp_cmd_operation(struct flb_exp *e1, struct flb_exp *e2,
                                     int operation);
struct flb_exp *flb_sp_cmd_comparison(struct flb_exp *key, struct flb_exp *val,
                                      int operation);
struct flb_exp *flb_sp_cmd_condition_key(char *key);
struct flb_exp *flb_sp_cmd_condition_integer(int integer);
struct flb_exp *flb_sp_cmd_condition_float(float fval);
struct flb_exp *flb_sp_cmd_condition_string(char *string);
struct flb_exp *flb_sp_cmd_condition_boolean(bool boolean);

#endif
