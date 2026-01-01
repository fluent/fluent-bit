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

#ifndef FLB_SP_PARSER_H
#define FLB_SP_PARSER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_window.h>

/* Aggregation functions */
#define FLB_SP_NOP       0
#define FLB_SP_AVG       1
#define FLB_SP_SUM       2
#define FLB_SP_COUNT     3
#define FLB_SP_MIN       4
#define FLB_SP_MAX       5
#define FLB_SP_FORECAST  6

/* Update this whenever a new aggregate function is added */
#define AGGREGATE_FUNCTIONS    6

/* Date time functions */
#define FLB_SP_NOW             10
#define FLB_SP_UNIX_TIMESTAMP  11

/* Record functions */
#define FLB_SP_RECORD_TAG      20
#define FLB_SP_RECORD_TIME     21

/* Status */
#define FLB_SP_OK            0
#define FLB_SP_ERROR        -1

/* Command type */
#define FLB_SP_SELECT          0
#define FLB_SP_CREATE_STREAM   1
#define FLB_SP_CREATE_SNAPSHOT 2
#define FLB_SP_FLUSH_SNAPSHOT  3

/* Source type */
#define FLB_SP_STREAM    0
#define FLB_SP_TAG       1

/* Parameter type */
#define FLB_SP_KEY    0
#define FLB_SP_VAL    1

/* Expression type */
enum Expressions {
    FLB_LOGICAL_OP = 0,
    FLB_EXP_KEY,
    FLB_EXP_BOOL,
    FLB_EXP_INT,
    FLB_EXP_FLOAT,
    FLB_EXP_STRING,
    FLB_EXP_NULL,
    FLB_EXP_FUNC,
    FLB_EXP_PARAM,
};

/* Logical operation */
enum Operations {
    FLB_EXP_PAR = 0,

    FLB_EXP_NOT,
    FLB_EXP_AND,
    FLB_EXP_OR,

    FLB_EXP_EQ,
    FLB_EXP_LT,
    FLB_EXP_LTE,
    FLB_EXP_GT,
    FLB_EXP_GTE,

    FLB_EXP_IS_NULL,
    FLB_EXP_IS_NOT_NULL
};

#define FLB_SP_TIME_SECOND  0
#define FLB_SP_TIME_MINUTE  1
#define FLB_SP_TIME_HOUR    2

/* Groupby key */
struct flb_sp_cmd_gb_key {
    flb_sds_t name;           /* key name */
    struct mk_list _head;     /* Link to flb_sp_cmd->gb_keys */
    int id;                   /* Position */
    void *gb_nums;
    struct mk_list *subkeys;  /* sub-keys selection */
};

/* Property (key/value) */
struct flb_sp_cmd_prop {
    flb_sds_t key;            /* key name */
    flb_sds_t val;            /* value name */
    struct mk_list _head;     /* Link to flb_sp_cmd->stream_props */
};

/* Key selection */
struct flb_sp_cmd_key {
    int aggr_func;             /* Aggregation function */
    int time_func;             /* Time function */
    int record_func;           /* Record function */
    flb_sds_t name;            /* Parent Key name */
    flb_sds_t alias;           /* Key output alias (key AS alias) */
    void *gb_key;              /* Key name reference to gb_key */
    // TODO: make it a general union type (or array of values)
    int constant;              /* constant parameter value
                                  (used specifically for timeseries_forecast) */
    struct mk_list *subkeys;   /* sub-keys selection */
    struct mk_list _head;      /* Link to flb_sp_cmd->keys */
};

struct flb_sp_window {
    int type;
    time_t size;
    time_t advance_by;
};

struct flb_sp_cmd {
    int status;
    int type;                      /* FLB_SP_CREATE_STREAM or FLB_SP_SELECT */

    /* Stream creation */
    flb_sds_t stream_name;         /* Name for created stream */
    struct mk_list stream_props;   /* Stream properties: WITH(a='b',..) */

    /* Selection */
    struct mk_list keys;           /* list head of record fields */


    struct flb_exp *condition;     /* WHERE condition in select statement */
    struct mk_list cond_list;

    struct flb_sp_window window;   /* WINDOW window in select statement */

    struct mk_list gb_keys;        /* list head of group-by record fields */
    char *alias;

    /*
     * When parsing a SQL statement that have references to keys with sub-keys
     * like record['a']['b']['c'], the following 'tmp_subkeys' list will hold
     * a list of the discovered sub-keys (linked list).
     *
     * When the parser gets into the parent field name (record), the list is
     * moved to the proper struct flb_sp_key->subkeys list pointer and this
     * field is re-created again as an empty list.
     */
    struct mk_list *tmp_subkeys;

    /* Limit on the number of records returning */
    int limit;

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
    struct mk_list _head;
    struct flb_exp *left;
    struct flb_exp *right;
};

struct flb_exp_op {
    int type;
    struct mk_list _head;
    struct flb_exp *left;
    struct flb_exp *right;
    int operation;
};

struct flb_exp_key {
    int type;
    struct mk_list _head;
    flb_sds_t name;
    struct mk_list *subkeys;
    int func;
};

struct flb_exp_func {
    int type;
    struct mk_list _head;
    flb_sds_t name;
    struct flb_exp_val *(*cb_func) (const char *, int,
                                    struct flb_time *, struct flb_exp_val *);
    struct flb_exp *param;
};

struct flb_exp_val {
    int type;
    struct mk_list _head;
    sp_val val;
};

/* Represent any value object */
struct flb_sp_value {
    int type;
    msgpack_object o;
    sp_val val;
};

struct flb_exp_param {
    int type;
    struct mk_list _head;
    struct flb_exp *param;
};

struct flb_sp_cmd *flb_sp_cmd_create(const char *sql);
void flb_sp_cmd_destroy(struct flb_sp_cmd *cmd);

/* Stream */
int flb_sp_cmd_stream_new(struct flb_sp_cmd *cmd, const char *stream_name);
int flb_sp_cmd_snapshot_new(struct flb_sp_cmd *cmd, const char *snapshot_name);
int flb_sp_cmd_snapshot_flush_new(struct flb_sp_cmd *cmd, const char *snapshot_name);
int flb_sp_cmd_stream_prop_add(struct flb_sp_cmd *cmd, const char *key, const char *val);
void flb_sp_cmd_stream_prop_del(struct flb_sp_cmd_prop *prop);
const char *flb_sp_cmd_stream_prop_get(struct flb_sp_cmd *cmd, const char *key);

/* Selection keys */
int flb_sp_cmd_key_add(struct flb_sp_cmd *cmd, int func, const char *key_name);
void flb_sp_cmd_key_del(struct flb_sp_cmd_key *key);
void flb_sp_cmd_alias_add(struct flb_sp_cmd *cmd, const char *key_alias);
int flb_sp_cmd_source(struct flb_sp_cmd *cmd, int type, const char *source);
void flb_sp_cmd_dump(struct flb_sp_cmd *cmd);

int flb_sp_cmd_window(struct flb_sp_cmd *cmd, int window_type,
                      int size, int time_unit,
                      int advance_by_size, int advance_by_time_unit);

void flb_sp_cmd_condition_add(struct flb_sp_cmd *cmd, struct flb_exp *e);
struct flb_exp *flb_sp_cmd_operation(struct flb_sp_cmd *cmd,
                                     struct flb_exp *e1, struct flb_exp *e2,
                                     int operation);
struct flb_exp *flb_sp_cmd_comparison(struct flb_sp_cmd *cmd,
                                      struct flb_exp *key, struct flb_exp *val,
                                      int operation);
struct flb_exp *flb_sp_cmd_condition_key(struct flb_sp_cmd *cmd, const char *key);
struct flb_exp *flb_sp_cmd_condition_integer(struct flb_sp_cmd *cmd,
                                             int integer);
struct flb_exp *flb_sp_cmd_condition_float(struct flb_sp_cmd *cmd, float fval);
struct flb_exp *flb_sp_cmd_condition_string(struct flb_sp_cmd *cmd,
                                            const char *string);
struct flb_exp *flb_sp_cmd_condition_boolean(struct flb_sp_cmd *cmd,
                                             bool boolean);
struct flb_exp *flb_sp_cmd_condition_null(struct flb_sp_cmd *cmd);
struct flb_exp *flb_sp_record_function_add(struct flb_sp_cmd *cmd,
                                           char *name, struct flb_exp *param);

void flb_sp_cmd_condition_del(struct flb_sp_cmd *cmd);

int flb_sp_cmd_gb_key_add(struct flb_sp_cmd *cmd, const char *key);
void flb_sp_cmd_gb_key_del(struct flb_sp_cmd_gb_key *key);

void flb_sp_cmd_limit_add(struct flb_sp_cmd *cmd, int limit);

int flb_sp_cmd_timeseries_forecast(struct flb_sp_cmd *cmd, int func,
                                   const char *key_name, int seconds);

#endif
