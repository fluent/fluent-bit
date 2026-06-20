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

#ifndef FLB_PROCESSOR_SQL_H
#define FLB_PROCESSOR_SQL_H

#include <fluent-bit/flb_processor_plugin.h>

/* Status */
#define SQL_SP_OK            0
#define SQL_SP_ERROR        -1

/* Expression type */
enum sql_expressions {
    SQL_LOGICAL_OP = 0,
    SQL_EXP_KEY,
    SQL_EXP_BOOL,
    SQL_EXP_INT,
    SQL_EXP_FLOAT,
    SQL_EXP_STRING,
    SQL_EXP_NULL,
    SQL_EXP_FUNC,
    SQL_EXP_PARAM,
};

/* Logical operation */
enum sql_operations {
    SQL_EXP_PAR = 0,

    SQL_EXP_NOT,
    SQL_EXP_AND,
    SQL_EXP_OR,

    SQL_EXP_EQ,
    SQL_EXP_LT,
    SQL_EXP_LTE,
    SQL_EXP_GT,
    SQL_EXP_GTE,

    SQL_EXP_IS_NULL,
    SQL_EXP_IS_NOT_NULL
};

/* condition value types */
typedef union {
    bool boolean;
    int64_t i64;
    double f64;
    cfl_sds_t string;
} sql_val;

struct sql_expression {
    int type;
    struct cfl_list _head;

    struct sql_expression *left;
    struct sql_expression *right;

};

struct sql_expression_key {
    int type;
    struct cfl_list _head;

    cfl_sds_t name;
    struct mk_list *subkeys;
    int func;
};

struct sql_expression_val {
    int type;
    struct cfl_list _head;

    sql_val val;

};

struct sql_expression_op {
    int type;
    struct cfl_list _head;

    struct sql_expression *left;
    struct sql_expression *right;
    int operation;
};

struct sql_key {
    cfl_sds_t name;
    cfl_sds_t alias;
    struct cfl_list _head;
};

/* Represent any value object */
struct sql_value {
    int type;
    msgpack_object o; /* mighyt need to vbe changed to a cfl variant */
    sql_val val;
};

struct sql_query {
    int status;
    struct cfl_list keys;
    struct cfl_list cond_list;

    struct sql_expression *condition;     /* WHERE condition in select statement */

    /*
     * one caller uses flb_slist that works on top of mk_list instead
     * of the new CFL.
     */
    struct mk_list *tmp_subkeys;
};

struct sql_ctx {
    struct sql_query *query;

    cfl_sds_t query_str;
    struct flb_processor_instance *ins;
};

#endif
