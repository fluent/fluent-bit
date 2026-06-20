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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_mem.h>

#include "sql.h"

static int swap_tmp_subkeys(struct mk_list **target, struct sql_query *query)
{
    /* Map context keys into this command key structure */
    *target = query->tmp_subkeys;

    query->tmp_subkeys = flb_malloc(sizeof(struct mk_list));
    if (!query->tmp_subkeys) {
        flb_errno();
        query->tmp_subkeys = *target;
        query->status = SQL_SP_ERROR;
        return -1;
    }

    flb_slist_create(query->tmp_subkeys);
    return 0;
}

/* WHERE <condition> functions */

struct sql_expression *sql_expression_operation(struct sql_query *query,
                                                struct sql_expression *e1,
                                                struct sql_expression *e2,
                                                int operation)
{
    struct sql_expression_op *expression;

    expression = flb_calloc(1, sizeof(struct sql_expression_op));
    if (!expression) {
        flb_errno();
        return NULL;
    }

    expression->type = SQL_LOGICAL_OP;
    expression->left = e1;
    expression->right = e2;
    expression->operation = operation;

    cfl_list_add(&expression->_head, &query->cond_list);

    return (struct sql_expression *) expression;
}

void sql_expression_condition_add(struct sql_query *query, struct sql_expression *e)

{
    query->condition = e;
}

struct sql_expression *sql_expression_condition_key(struct sql_query *query,
                                                    const char *identifier)
{
    int ret;
    struct sql_expression_key *key;

    key = flb_calloc(1, sizeof(struct sql_expression_key));
    if (!key) {
        flb_errno();
        return NULL;
    }

    key->type = SQL_EXP_KEY;
    key->name = cfl_sds_create(identifier);
    cfl_list_add(&key->_head, &query->cond_list);

    if (query->tmp_subkeys && mk_list_size(query->tmp_subkeys) > 0) {
        ret = swap_tmp_subkeys(&key->subkeys, query);
        if (ret == -1) {
            cfl_sds_destroy(key->name);
            cfl_list_del(&key->_head);
            flb_free(key);
            return NULL;
        }
    }

    return (struct sql_expression *) key;
}

struct sql_expression *sql_expression_condition_integer(struct sql_query *query,
                                                        int integer)
{
    struct sql_expression_val *val;

    val = flb_calloc(1, sizeof(struct sql_expression_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = SQL_EXP_INT;
    val->val.i64 = integer;
    cfl_list_add(&val->_head, &query->cond_list);

    return (struct sql_expression *) val;
}

struct sql_expression *sql_expression_condition_float(struct sql_query *query,
                                                      float fval)
{
    struct sql_expression_val *val;

    val = flb_calloc(1, sizeof(struct sql_expression_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = SQL_EXP_FLOAT;
    val->val.f64 = fval;
    cfl_list_add(&val->_head, &query->cond_list);

    return (struct sql_expression *) val;
}

struct sql_expression *sql_expression_condition_string(struct sql_query *query,
                                                       const char *string)
{
    struct sql_expression_val *val;

    val = flb_malloc(sizeof(struct sql_expression_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = SQL_EXP_STRING;
    val->val.string = cfl_sds_create(string);
    if (!val->val.string) {
        flb_errno();
        flb_free(val);
        return NULL;
    }

    cfl_list_add(&val->_head, &query->cond_list);

    return (struct sql_expression *) val;
}


struct sql_expression *sql_expression_condition_boolean(struct sql_query *query,
                                                        int boolean)
{
    struct sql_expression_val *val;

    val = flb_malloc(sizeof(struct sql_expression_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = SQL_EXP_BOOL;
    val->val.boolean = boolean;
    cfl_list_add(&val->_head, &query->cond_list);

    return (struct sql_expression *) val;
}

struct sql_expression *sql_expression_condition_null(struct sql_query *query)
{
    struct sql_expression_val *val;

    val = flb_calloc(1, sizeof(struct sql_expression_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = SQL_EXP_NULL;
    cfl_list_add(&val->_head, &query->cond_list);

    return (struct sql_expression *) val;
}

struct sql_expression *sql_expression_comparison(struct sql_query *query,
                                                 struct sql_expression *key,
                                                 struct sql_expression *val,
                                                 int operation)
{
    struct sql_expression_op *expression;

    expression = flb_calloc(1, sizeof(struct sql_expression_op));
    if (!expression) {
        flb_errno();
        return NULL;
    }

    expression->type = SQL_LOGICAL_OP;
    expression->left = (struct sql_expression *) key;
    expression->right = (struct sql_expression *) val;
    expression->operation = operation;
    cfl_list_add(&expression->_head, &query->cond_list);

    return (struct sql_expression *) expression;
}