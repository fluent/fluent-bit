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
#include "sql_config.h"

/* String type to numerical conversion */
#define SQL_STR_INT   1
#define SQL_STR_FLOAT 2

static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    struct sql_ctx *ctx;

    ctx = sql_config_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_processor_instance_set_context(ins, ctx);

    return FLB_PROCESSOR_SUCCESS;
}

/* Processor exit */
static int cb_exit(struct flb_processor_instance *ins, void *data   )
{
    struct sql_ctx *ctx = (struct sql_ctx *) data;

    if (!ctx) {
        return FLB_PROCESSOR_SUCCESS;
    }

    sql_config_destroy(ctx);
    return FLB_PROCESSOR_SUCCESS;
}

void sql_expression_val_free(struct sql_expression_val *v)
{
    if (!v) {
        return;
    }

    if (v->type == SQL_EXP_STRING) {
        cfl_sds_destroy(v->val.string);
    }

    flb_free(v);
}

/*
 * Convert a string to a numerical representation:
 *
 * - if output number is an integer, 'i' is set and returns FLB_STR_INT
 * - if output number is a float, 'd' is set and returns FLB_STR_FLOAT
 * - if no conversion is possible (not a number), returns -1
 */
static int string_to_number(const char *str, int len, int64_t *i, double *d)
{
    int c;
    int dots = 0;
    char *end;
    int64_t i_out;
    double d_out;

    /* Detect if this is a floating point number */
    for (c = 0; c < len; c++) {
        if (str[c] == '.') {
            dots++;
        }
    }

    if (dots > 1) {
        return -1;
    }
    else if (dots == 1) {
        /* Floating point number */
        errno = 0;
        d_out = strtold(str, &end);

        /* Check for various possible errors */
        if ((errno == ERANGE || (errno != 0 && d_out == 0))) {
            return -1;
        }

        if (end == str) {
            return -1;
        }

        *d = d_out;
        return SQL_STR_FLOAT;
    }
    else {
        /* Integer */
        errno = 0;
        i_out = strtoll(str, &end, 10);

        /* Check for various possible errors */
        if ((errno == ERANGE || (errno != 0 && i_out == 0))) {
            return -1;
        }

        if (end == str) {
            return -1;
        }

        *i = i_out;
        return SQL_STR_INT;
    }

    return -1;
}

/* Convert (string) expression to number */
static void exp_string_to_number(struct sql_expression_val *val)
{
    int ret;
    int len;
    int64_t i = 0;
    char *str;
    double d = 0.0;

    len = flb_sds_len(val->val.string);
    str = val->val.string;

    ret = string_to_number(str, len, &i, &d);
    if (ret == -1) {
        return;
    }

    /* Assign to proper type */
    if (ret == SQL_STR_FLOAT) {
        flb_sds_destroy(val->val.string);
        val->type = SQL_EXP_FLOAT;
        val->val.f64 = d;
    }
    else if (ret == SQL_STR_INT) {
        flb_sds_destroy(val->val.string);
        val->type = SQL_EXP_INT;
        val->val.i64 = i;
    }
}



static bool value_to_bool(struct sql_expression_val *val) {
    bool result = FLB_FALSE;

    switch (val->type) {
    case SQL_EXP_BOOL:
        result = val->val.boolean;
        break;
    case SQL_EXP_INT:
        result = val->val.i64 > 0;
        break;
    case SQL_EXP_FLOAT:
        result = val->val.f64 > 0;
        break;
    case SQL_EXP_STRING:
        result = true;
        break;
    }

    return result;
}
static void itof_convert(struct sql_expression_val *val)
{
    if (val->type != SQL_EXP_INT) {
        return;
    }

    val->type = SQL_EXP_FLOAT;
    val->val.f64 = (double) val->val.i64;
}

static void numerical_comp(struct sql_expression_val *left,
                           struct sql_expression_val *right,
                           struct sql_expression_val *result, int op)
{
    result->type = SQL_EXP_BOOL;

    if (left == NULL || right == NULL) {
        result->val.boolean = false;
        return;
    }

    /* Check if left expression value is a number, if so, convert it */
    if (left->type == SQL_EXP_STRING && right->type != SQL_EXP_STRING) {
        exp_string_to_number(left);
    }

    if (left->type == SQL_EXP_INT && right->type == SQL_EXP_FLOAT) {
        itof_convert(left);
    }
    else if (left->type == SQL_EXP_FLOAT && right->type == SQL_EXP_INT) {
        itof_convert(right);
    }

    switch (op) {
    case SQL_EXP_EQ:
        if (left->type == right->type) {
            switch(left->type) {
            case SQL_EXP_NULL:
                result->val.boolean = true;
                break;
            case SQL_EXP_BOOL:
                result->val.boolean = (left->val.boolean == right->val.boolean);
                break;
            case SQL_EXP_INT:
                result->val.boolean = (left->val.i64 == right->val.i64);
                break;
            case SQL_EXP_FLOAT:
                result->val.boolean = (left->val.f64 == right->val.f64);
                break;
            case SQL_EXP_STRING:
                if (flb_sds_len(left->val.string) !=
                    flb_sds_len(right->val.string)) {
                    result->val.boolean = false;
                }
                else if (strncmp(left->val.string, right->val.string,
                                 flb_sds_len(left->val.string)) != 0) {
                    result->val.boolean = false;
                }
                else {
                    result->val.boolean = true;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case SQL_EXP_LT:
        if (left->type == right->type) {
            switch(left->type) {
            case SQL_EXP_INT:
                result->val.boolean = (left->val.i64 < right->val.i64);
                break;
            case SQL_EXP_FLOAT:
                result->val.boolean = (left->val.f64 < right->val.f64);
                break;
            case SQL_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) < 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case SQL_EXP_LTE:
        if (left->type == right->type) {
            switch(left->type) {
            case SQL_EXP_INT:
                result->val.boolean = (left->val.i64 <= right->val.i64);
                break;
            case SQL_EXP_FLOAT:
                result->val.boolean = (left->val.f64 <= right->val.f64);
                break;
            case SQL_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) <= 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case SQL_EXP_GT:
        if (left->type == right->type) {
            switch(left->type) {
            case SQL_EXP_INT:
                result->val.boolean = (left->val.i64 > right->val.i64);
                break;
            case SQL_EXP_FLOAT:
                result->val.boolean = (left->val.f64 > right->val.f64);
                break;
            case SQL_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) > 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    case SQL_EXP_GTE:
        if (left->type == right->type) {
            switch(left->type) {
            case SQL_EXP_INT:
                result->val.boolean = (left->val.i64 >= right->val.i64);
                break;
            case SQL_EXP_FLOAT:
                result->val.boolean = (left->val.f64 >= right->val.f64);
                break;
            case SQL_EXP_STRING:
                if (strncmp(left->val.string, right->val.string,
                            flb_sds_len(left->val.string)) >= 0) {
                    result->val.boolean = true;
                }
                else {
                    result->val.boolean = false;
                }
                break;
            default:
                result->val.boolean = false;
                break;
            }
        }
        else {
            result->val.boolean = false;
        }
        break;
    }
}

static void logical_operation(struct sql_expression_val *left,
                              struct sql_expression_val *right,
                              struct sql_expression_val *result, int op)
{
    bool lval;
    bool rval;

    result->type = SQL_EXP_BOOL;

    /* Null is always interpreted as false in a logical operation */
    lval = left ? value_to_bool(left) : false;
    rval = right ? value_to_bool(right) : false;

    switch (op) {
    case SQL_EXP_NOT:
        result->val.boolean = !lval;
        break;
    case SQL_EXP_AND:
        result->val.boolean = lval & rval;
        break;
    case SQL_EXP_OR:
        result->val.boolean = lval | rval;
        break;
    }
}

static int sql_key_to_value(char *name, struct flb_mp_chunk_record *record, struct sql_expression_val *val)
{

    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_variant *var;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;

    kvlist = record->cobj_record->variant->data.as_kvlist;

    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(kvpair->key) != cfl_sds_len(name)) {
            var = NULL;
            continue;
        }

        if (strcmp(kvpair->key, name) != 0) {
            var = NULL;
            continue;
        }

        var = kvpair->val;
        break;
    }

    if (!var) {
        return -1;
    }

    if (var->type == CFL_VARIANT_STRING) {
        val->type = SQL_EXP_STRING;
        val->val.string = cfl_sds_create(kvpair->val->data.as_string);
    }
    else if (var->type == CFL_VARIANT_INT) {
        val->type = SQL_EXP_INT;
        val->val.i64 = kvpair->val->data.as_int64;
    }
    else if (var->type == CFL_VARIANT_UINT) {
        /*
         * Note on uint64 handling: our parsing rules in sql-parser.l handles the strings
         * that represents integers through an atol() conversion. If we get a case of a
         * long unsigned value, we can adjust it here by extending the sql_val union.
         *
         */
        val->type = SQL_EXP_INT;
        val->val.i64 = kvpair->val->data.as_uint64;
    }
    else if (var->type == CFL_VARIANT_DOUBLE) {
        val->type = SQL_EXP_FLOAT;
        val->val.f64 = kvpair->val->data.as_double;
    }
    else if (var->type == CFL_VARIANT_BOOL) {
        val->type = SQL_EXP_BOOL;
        val->val.boolean = kvpair->val->data.as_bool;
    }
    else if (var->type == CFL_VARIANT_NULL) {
        val->type = SQL_EXP_NULL;
        val->val.boolean = 1;
    }
    else {
        return -1;
    }

    return 0;
}

static struct sql_expression_val *reduce_expression(struct sql_expression *expression,
                                                    struct flb_mp_chunk_record *record)

{
    int ret;
    int operation;
    flb_sds_t s;
    struct sql_expression_key *key;
    struct sql_expression_val *left;
    struct sql_expression_val *right;
    struct sql_expression_val *result;

    if (!expression) {
        return NULL;
    }

    result = flb_calloc(1, sizeof(struct sql_expression_val));
    if (!result) {
        flb_errno();
        return NULL;
    }

    switch (expression->type) {
    case SQL_EXP_NULL:
        result->type = expression->type;
        break;
    case SQL_EXP_BOOL:
        result->type = expression->type;
        result->val.boolean = ((struct sql_expression_val *) expression)->val.boolean;
        break;
    case SQL_EXP_INT:
        result->type = expression->type;
        result->val.i64 = ((struct sql_expression_val *) expression)->val.i64;
        break;
    case SQL_EXP_FLOAT:
        result->type = expression->type;
        result->val.f64 = ((struct sql_expression_val *) expression)->val.f64;
        break;
    case SQL_EXP_STRING:
        s = ((struct sql_expression_val *) expression)->val.string;
        result->type = expression->type;
        result->val.string = cfl_sds_create(s);
        break;
    case SQL_EXP_KEY:
        key = (struct sql_expression_key *) expression;
        ret = sql_key_to_value(key->name, record, result);
        if (ret == 0) {
            return result;
        }
        else {
            flb_free(result);
            return NULL;
        }
        break;
    /* Functions are to be defined
    case SQL_EXP_FUNC:
        we don't need result
        flb_free(result);
        ret = reduce_expression(((struct sql_func *) expression)->param,
                                tag, tag_len, tms, map);
        result = ((struct SQL_EXP_func *) expression)->cb_func(tag, tag_len,
                                                               tms, ret);
        sql_expression_val_free(ret);
        break;
    */
    case SQL_LOGICAL_OP:
        left = reduce_expression(expression->left, record);
        right = reduce_expression(expression->right, record);

        operation = ((struct sql_expression_op *) expression)->operation;

        switch (operation) {
        case SQL_EXP_PAR:
            if (left == NULL) { /* Null is always interpreted as false in a
                                   logical operation */
                result->type = SQL_EXP_BOOL;
                result->val.boolean = false;
            }
            else { /* Left and right sides of a logical operation reduce to
                      boolean values */
                result->type = SQL_EXP_BOOL;
                result->val.boolean = left->val.boolean;
            }
            break;
        case SQL_EXP_EQ:
        case SQL_EXP_LT:
        case SQL_EXP_LTE:
        case SQL_EXP_GT:
        case SQL_EXP_GTE:
            numerical_comp(left, right, result, operation);
            break;
        case SQL_EXP_NOT:
        case SQL_EXP_AND:
        case SQL_EXP_OR:
            logical_operation(left, right, result, operation);
            break;
        }
        sql_expression_val_free(left);
        sql_expression_val_free(right);
        break;
    default:
        break;
    }

    return result;
}


static int process_record(struct sql_ctx *ctx, struct sql_query *query, struct flb_mp_chunk_record *chunk_record)
{
    int found = FLB_FALSE;
    struct sql_key *key;
    struct cfl_list *tmp;
    struct cfl_list *tmp_var;
    struct cfl_list *head;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;
    struct cfl_list *head_var;
    struct sql_expression_val *condition;


    /* check if the query contains a conditional statement */
    if (query->condition) {
        condition = reduce_expression(query->condition, chunk_record);
        if (!condition) {
            return 0;
        }
        else if (!condition->val.boolean) {
            flb_free(condition);
            return -1;
        }
        else {
            flb_free(condition);
        }

    }

    /*
     * iterate all the record keys and see if they are listed in the selected keys,
     * otherwise check if a wildcard has been used so all the keys will match.
     *
     * if no matches exists, just remove the record.
     */
    kvlist = chunk_record->cobj_record->variant->data.as_kvlist;


    cfl_list_foreach_safe(head, tmp, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        found = FLB_FALSE;

        /* check if we have a wildcard */
        if (cfl_list_size(&query->keys) > 0) {
            key = cfl_list_entry_first(&query->keys, struct sql_key, _head);
            if (key->name == NULL) {
                found = FLB_TRUE;
            }
        }

        if (found == FLB_FALSE) {
            cfl_list_foreach_safe(head_var, tmp_var, &ctx->query->keys) {
                key = cfl_list_entry(head_var, struct sql_key, _head);

                if (cfl_sds_len(kvpair->key) != cfl_sds_len(key->name)) {
                    continue;
                }

                if (strcmp(kvpair->key, key->name) == 0) {
                    found = FLB_TRUE;
                    break;
                }
            }
        }

        if (!found) {
            cfl_kvpair_destroy(kvpair);
        }
        else {
            /* we keep the key in the list, check if it needs an alias */
            if (key->alias) {
                cfl_sds_destroy(kvpair->key);
                kvpair->key = cfl_sds_create(key->alias);
            }
        }
    }

    return 0;
}

/* Logs callback */
static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data,
                           const char *tag,
                           int tag_len)
{
    int ret;
    struct sql_ctx *ctx;
    struct flb_mp_chunk_cobj *chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;
    struct flb_mp_chunk_record *record;
    ctx = ins->context;

    /* Iterate records */
    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {
        ret = process_record(ctx, ctx->query, record);
        if (ret == -1) {
          /* remove the record from the chunk */
          flb_mp_chunk_cobj_record_destroy(chunk_cobj, record);
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}


static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "query", NULL,
        0, FLB_TRUE, offsetof(struct sql_ctx, query_str),
        "SQL query for data selection."
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_sql_plugin = {
    .name               = "sql",
    .description        = "SQL processor",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};

