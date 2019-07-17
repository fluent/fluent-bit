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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>
#include <fluent-bit/stream_processor/flb_sp_record_func.h>

#include "sql_parser.h"
#include "sql_lex.h"

void flb_sp_cmd_destroy(struct flb_sp_cmd *cmd)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_sp_cmd_key *key;
    struct flb_sp_cmd_gb_key *gb_key;
    struct flb_sp_cmd_prop *prop;

    /* remove keys */
    mk_list_foreach_safe(head, tmp, &cmd->keys) {
        key = mk_list_entry(head, struct flb_sp_cmd_key, _head);
        mk_list_del(&key->_head);
        flb_sp_cmd_key_del(key);
    }

    /* remove groupby keys */
    mk_list_foreach_safe(head, tmp, &cmd->gb_keys) {
        gb_key = mk_list_entry(head, struct flb_sp_cmd_gb_key, _head);
        mk_list_del(&gb_key->_head);
        flb_sp_cmd_gb_key_del(gb_key);
    }

    /* stream */
    if (cmd->stream_name) {
        mk_list_foreach_safe(head, tmp, &cmd->stream_props) {
            prop = mk_list_entry(head, struct flb_sp_cmd_prop, _head);
            mk_list_del(&prop->_head);
            flb_sp_cmd_stream_prop_del(prop);
        }
        flb_sds_destroy(cmd->stream_name);
    }
    flb_sds_destroy(cmd->source_name);

    if (mk_list_size(&cmd->cond_list) > 0) {
        flb_sp_cmd_condition_del(cmd);
    }

    if (cmd->tmp_subkeys) {
        flb_slist_destroy(cmd->tmp_subkeys);
        flb_free(cmd->tmp_subkeys);
    }

    flb_free(cmd);
}

void flb_sp_cmd_key_del(struct flb_sp_cmd_key *key)
{
    if (key->name) {
        flb_sds_destroy(key->name);
    }
    if (key->alias) {
        flb_sds_destroy(key->alias);
    }
    if (key->name_keys) {
        flb_sds_destroy(key->name_keys);
    }
    if (key->subkeys) {
        flb_slist_destroy(key->subkeys);
        flb_free(key->subkeys);
    }
    flb_free(key);
}

void flb_sp_cmd_gb_key_del(struct flb_sp_cmd_gb_key *key)
{
    if (key->name) {
        flb_sds_destroy(key->name);
    }
    flb_free(key);
}

int flb_sp_cmd_key_add(struct flb_sp_cmd *cmd, int func,
                       const char *key_name, const char *key_alias)
{
    int s;
    int aggr_func = 0;
    int time_func = 0;
    int record_func = 0;
    char *tmp;
    struct mk_list *head;
    struct flb_sp_cmd_key *key;
    struct flb_slist_entry *entry;

    /* aggregation function ? */
    if (func >= FLB_SP_AVG && func <= FLB_SP_MAX) {
        aggr_func = func;
    }
    else if (func >= FLB_SP_NOW && func <= FLB_SP_UNIX_TIMESTAMP) {
        /* Time function */
        time_func = func;
    }
    else if (func >= FLB_SP_RECORD_TAG && func <= FLB_SP_RECORD_TIME) {
        /* Record function */
        record_func = func;
    }

    key = flb_calloc(1, sizeof(struct flb_sp_cmd_key));
    if (!key) {
        flb_errno();
        cmd->status = FLB_SP_ERROR;
        return -1;
    }
    key->subkeys = NULL;

    /* key name and aliases works when the selection is not a wildcard */
    if (key_name) {
        key->name = flb_sds_create(key_name);
        if (!key->name) {
            flb_sp_cmd_key_del(key);
            cmd->status = FLB_SP_ERROR;
            return -1;
        }
    }
    else {
        /*
         * Wildcard key only allowed on:
         * - no aggregation mode (left side / first entry)
         * - aggregation using COUNT(*)
         */
        if (mk_list_size(&cmd->keys) > 0 && aggr_func == 0 &&
            record_func == 0 && time_func == 0) {
            flb_sp_cmd_key_del(key);
            cmd->status = FLB_SP_ERROR;
            return -1;
        }
    }

    if (key_alias) {
        key->alias = flb_sds_create(key_alias);
        if (!key->alias) {
            flb_sp_cmd_key_del(key);
            cmd->status = FLB_SP_ERROR;
            return -1;
        }
    }

    /* Aggregation function */
    if (aggr_func > 0) {
        key->aggr_func = aggr_func;
    }
    else if (time_func > 0) {
        key->time_func = time_func;
    }
    else if (record_func > 0) {
        key->record_func = record_func;
    }

    /* Lookup for any subkeys in the temporal list */
    if (mk_list_size(cmd->tmp_subkeys) > 0) {
        /* Map context keys into this command key structure */
        key->subkeys = cmd->tmp_subkeys;
        cmd->tmp_subkeys = flb_malloc(sizeof(struct mk_list));
        if (!cmd->tmp_subkeys) {
            flb_errno();
            cmd->tmp_subkeys = key->subkeys;
            flb_sp_cmd_key_del(key);
            cmd->status = FLB_SP_ERROR;
            return -1;
        }
        flb_slist_create(cmd->tmp_subkeys);

        /* Compose a name key that include listed sub keys */
        s = flb_sds_len(key->name) + (16 * mk_list_size(key->subkeys));
        key->name_keys = flb_sds_create_size(s);
        if (!key->name_keys) {
            flb_sp_cmd_key_del(key);
            return -1;
        }

        tmp = flb_sds_cat(key->name_keys, key->name, flb_sds_len(key->name));
        if (tmp != key->name_keys) {
            key->name_keys = tmp;
        }

        mk_list_foreach(head, key->subkeys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);

            /* prefix */
            tmp = flb_sds_cat(key->name_keys, "['", 2);
            if (tmp) {
                key->name_keys = tmp;
            }
            else {
                flb_sp_cmd_key_del(key);
                return -1;
            }

            /* selected key name */
            tmp = flb_sds_cat(key->name_keys,
                              entry->str, flb_sds_len(entry->str));
            if (tmp) {
                key->name_keys = tmp;
            }
            else {
                flb_sp_cmd_key_del(key);
                return -1;
            }

            /* suffix */
            tmp = flb_sds_cat(key->name_keys, "']", 2);
            if (tmp) {
                key->name_keys = tmp;
            }
            else {
                flb_sp_cmd_key_del(key);
                return -1;
            }
        }
    }

    mk_list_add(&key->_head, &cmd->keys);
    return 0;
}

int flb_sp_cmd_source(struct flb_sp_cmd *cmd, int type, const char *source)
{
    cmd->source_type = type;
    cmd->source_name = flb_sds_create(source);
    if (!cmd->source_name) {
        flb_errno();
        return -1;
    }

    return 0;
}

void flb_sp_cmd_dump(struct flb_sp_cmd *cmd)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_sp_cmd_key *key;

    /* Lookup keys */
    printf("== KEYS ==\n");
    mk_list_foreach_safe(head, tmp, &cmd->keys) {
        key = mk_list_entry(head, struct flb_sp_cmd_key, _head);
        printf("- '%s'\n", key->name);
    }
    printf("== SOURCE ==\n");
    if (cmd->source_type == FLB_SP_STREAM) {
        printf("stream => ");
    }
    else if (cmd->source_type == FLB_SP_TAG) {
        printf("tag match => ");
    }

    printf("'%s'\n", cmd->source_name);
}

struct flb_sp_cmd *flb_sp_cmd_create(const char *sql)
{
    int ret;
    yyscan_t scanner;
    YY_BUFFER_STATE buf;
    struct flb_sp_cmd *cmd;

    /* create context */
    cmd = flb_calloc(1, sizeof(struct flb_sp_cmd));
    if (!cmd) {
        flb_errno();
        return NULL;
    }
    cmd->status = FLB_SP_OK;
    cmd->type = FLB_SP_SELECT;

    mk_list_init(&cmd->stream_props);
    mk_list_init(&cmd->keys);

    /* Condition linked list (we use them to free resources) */
    mk_list_init(&cmd->cond_list);

    mk_list_init(&cmd->gb_keys);

    /* Allocate temporal list and initialize */
    cmd->tmp_subkeys = flb_malloc(sizeof(struct mk_list));
    if (!cmd->tmp_subkeys) {
        flb_errno();
        flb_free(cmd);
        return NULL;
    }
    flb_slist_create(cmd->tmp_subkeys);

    /* Flex/Bison work */
    yylex_init(&scanner);
    buf = yy_scan_string(sql, scanner);

    ret = yyparse(cmd, sql, scanner);

    yy_delete_buffer(buf, scanner);
    yylex_destroy(scanner);

    if (ret != 0) {
        flb_sp_cmd_destroy(cmd);
        return NULL;
    }

    return cmd;
}

int flb_sp_cmd_stream_new(struct flb_sp_cmd *cmd, const char *stream_name)
{
    cmd->stream_name = flb_sds_create(stream_name);
    if (!cmd->stream_name) {
        return -1;
    }

    cmd->type = FLB_SP_CREATE_STREAM;
    return 0;
}

int flb_sp_cmd_stream_prop_add(struct flb_sp_cmd *cmd, const char *key, const char *val)
{
    struct flb_sp_cmd_prop *prop;

    prop = flb_malloc(sizeof(struct flb_sp_cmd_prop));
    if (!prop) {
        flb_errno();
        return -1;
    }

    prop->key = flb_sds_create(key);
    if (!prop->key) {
        flb_free(prop);
        return -1;
    }

    prop->val = flb_sds_create(val);
    if (!prop->val) {
        flb_free(prop->key);
        flb_free(prop);
        return -1;
    }

    mk_list_add(&prop->_head, &cmd->stream_props);
    return 0;
}

void flb_sp_cmd_stream_prop_del(struct flb_sp_cmd_prop *prop)
{
    if (prop->key) {
        flb_sds_destroy(prop->key);
    }
    if (prop->val) {
        flb_sds_destroy(prop->val);
    }
    flb_free(prop);
}

const char *flb_sp_cmd_stream_prop_get(struct flb_sp_cmd *cmd, const char *key)
{
    int len;
    struct mk_list *head;
    struct flb_sp_cmd_prop *prop;

    if (!key) {
        return NULL;
    }
    len = strlen(key);

    mk_list_foreach(head, &cmd->stream_props) {
        prop = mk_list_entry(head, struct flb_sp_cmd_prop, _head);
        if (flb_sds_len(prop->key) != len) {
            continue;
        }

        if (strcmp(prop->key, key) == 0) {
            return prop->val;
        }
    }

    return NULL;
}

/* WINDOW functions */

int flb_sp_cmd_window(struct flb_sp_cmd *cmd,
                      int window_type, int size, int time_unit,
                      int advance_by_size, int advance_by_time_unit)
{
    cmd->window.type = window_type;

    switch (time_unit) {
    case FLB_SP_TIME_SECOND:
        cmd->window.size = (time_t) size;
        break;
    case FLB_SP_TIME_MINUTE:
        cmd->window.size = (time_t) size * 60;
        break;
    case FLB_SP_TIME_HOUR:
        cmd->window.size = (time_t) size * 3600;
        break;
    }

    if (window_type == FLB_SP_WINDOW_HOPPING) {
        switch (advance_by_time_unit) {
        case FLB_SP_TIME_SECOND:
            cmd->window.advance_by = (time_t) advance_by_size;
            break;
        case FLB_SP_TIME_MINUTE:
            cmd->window.advance_by = (time_t) advance_by_size * 60;
            break;
        case FLB_SP_TIME_HOUR:
            cmd->window.advance_by = (time_t) advance_by_size * 3600;
            break;
        }

        if (cmd->window.advance_by >= cmd->window.size) {
            return -1;
        }
    }

    return 0;
}

/* WHERE <condition> functions */

struct flb_exp *flb_sp_cmd_operation(struct flb_sp_cmd *cmd,
                                     struct flb_exp *e1, struct flb_exp *e2,
                                     int operation)
{
    struct flb_exp_op *expression;

    expression = flb_malloc(sizeof(struct flb_exp_op));
    if (!expression) {
        flb_errno();
        return NULL;
    }

    expression->type = FLB_LOGICAL_OP;
    expression->left = e1;
    expression->right = e2;
    expression->operation = operation;
    mk_list_add(&expression->_head, &cmd->cond_list);

    return (struct flb_exp *) expression;
}

struct flb_exp *flb_sp_cmd_comparison(struct flb_sp_cmd *cmd,
                                      struct flb_exp *key, struct flb_exp *val,
                                      int operation)
{
    struct flb_exp_op *expression;

    expression = flb_malloc(sizeof(struct flb_exp_op));
    if (!expression) {
        flb_errno();
        return NULL;
    }

    expression->type = FLB_LOGICAL_OP;
    expression->left = (struct flb_exp *) key;
    expression->right = (struct flb_exp *) val;
    expression->operation = operation;
    mk_list_add(&expression->_head, &cmd->cond_list);

    return (struct flb_exp *) expression;
}

struct flb_exp *flb_sp_cmd_condition_key(struct flb_sp_cmd *cmd,
                                         const char *identifier)
{
    struct flb_exp_key *key;

    key = flb_calloc(1, sizeof(struct flb_exp_key));
    if (!key) {
        flb_errno();
        return NULL;
    }

    key->type = FLB_EXP_KEY;
    key->name = flb_sds_create(identifier);
    mk_list_add(&key->_head, &cmd->cond_list);

    /* Lookup for any subkeys in the temporal list */
    if (mk_list_size(cmd->tmp_subkeys) > 0) {
        key->subkeys = cmd->tmp_subkeys;
        cmd->tmp_subkeys = flb_malloc(sizeof(struct mk_list));
        if (!cmd->tmp_subkeys) {
            flb_errno();
            cmd->tmp_subkeys = key->subkeys;
            flb_sds_destroy(key->name);
            mk_list_del(&key->_head);
            flb_free(key);
            return NULL;
        }
        flb_slist_create(cmd->tmp_subkeys);
    }

    return (struct flb_exp *) key;
}

struct flb_exp *flb_sp_cmd_condition_integer(struct flb_sp_cmd *cmd,
                                             int integer)
{
    struct flb_exp_val *val;

    val = flb_malloc(sizeof(struct flb_exp_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = FLB_EXP_INT;
    val->val.i64 = integer;
    mk_list_add(&val->_head, &cmd->cond_list);

    return (struct flb_exp *) val;
}

struct flb_exp *flb_sp_cmd_condition_float(struct flb_sp_cmd *cmd, float fval)
{
    struct flb_exp_val *val;

    val = flb_malloc(sizeof(struct flb_exp_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = FLB_EXP_FLOAT;
    val->val.f64 = fval;
    mk_list_add(&val->_head, &cmd->cond_list);

    return (struct flb_exp *) val;
}

struct flb_exp *flb_sp_cmd_condition_string(struct flb_sp_cmd *cmd,
                                            const char *string)
{
    struct flb_exp_val *val;

    val = flb_malloc(sizeof(struct flb_exp_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = FLB_EXP_STRING;
    val->val.string = flb_sds_create(string);
    mk_list_add(&val->_head, &cmd->cond_list);

    return (struct flb_exp *) val;
}

struct flb_exp *flb_sp_cmd_condition_boolean(struct flb_sp_cmd *cmd,
                                             bool boolean)
{
    struct flb_exp_val *val;

    val = flb_malloc(sizeof(struct flb_exp_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = FLB_EXP_BOOL;
    val->val.boolean = boolean;
    mk_list_add(&val->_head, &cmd->cond_list);

    return (struct flb_exp *) val;
}

struct flb_exp *flb_sp_cmd_condition_null(struct flb_sp_cmd *cmd)
{
    struct flb_exp_val *val;

    val = flb_malloc(sizeof(struct flb_exp_val));
    if (!val) {
        flb_errno();
        return NULL;
    }

    val->type = FLB_EXP_NULL;
    mk_list_add(&val->_head, &cmd->cond_list);

    return (struct flb_exp *) val;
}

struct flb_exp *flb_sp_record_function_add(struct flb_sp_cmd *cmd,
                                           char *name, struct flb_exp *param)
{
    char *rf_name;
    int i;
    struct flb_exp_func *func;

    for (i = 0; i < RECORD_FUNCTIONS_SIZE; i++)
    {
        rf_name = record_functions[i];
        if (strncmp(rf_name, name, strlen(rf_name)) == 0)
        {
            func = flb_calloc(1, sizeof(struct flb_exp_func));
            if (!func) {
                flb_errno();
                return NULL;
            }

            func->type = FLB_EXP_FUNC;
            func->name = flb_sds_create(name);
            func->cb_func = record_functions_ptr[i];
            func->param = param;

            mk_list_add(&func->_head, &cmd->cond_list);

            return (struct flb_exp *) func;
        }
    }

    return NULL;
}

void flb_sp_cmd_condition_add(struct flb_sp_cmd *cmd, struct flb_exp *e)

{
    cmd->condition = e;
}

int flb_sp_cmd_gb_key_add(struct flb_sp_cmd *cmd, const char *key)
{
    struct flb_sp_cmd_gb_key *gb_key;

    gb_key = flb_malloc(sizeof(struct flb_sp_cmd_gb_key));
    if (!gb_key) {
        flb_errno();
        return -1;
    }

    gb_key->name = flb_sds_create(key);
    if (!gb_key->name) {
        flb_free(gb_key);
        return -1;
    }

    mk_list_add(&gb_key->_head, &cmd->gb_keys);
    return 0;
}

void flb_sp_cmd_condition_del(struct flb_sp_cmd *cmd)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_exp *exp;
    struct flb_exp_key *key;
    struct flb_exp_val *val;
    struct flb_exp_func *func;

    mk_list_foreach_safe(head, tmp, &cmd->cond_list) {
        exp = mk_list_entry(head, struct flb_exp, _head);
        if (exp->type == FLB_EXP_KEY) {
            key = (struct flb_exp_key *) exp;
            flb_sds_destroy(key->name);
            if (key->subkeys) {
                flb_slist_destroy(key->subkeys);
                flb_free(key->subkeys);
            }
        }
        else if (exp->type == FLB_EXP_STRING) {
            val = (struct flb_exp_val *) exp;
            flb_sds_destroy(val->val.string);
        }
        else if (exp->type == FLB_EXP_FUNC) {
            func = (struct flb_exp_func *) exp;
            flb_sds_destroy(func->name);
        }

        mk_list_del(&exp->_head);
        flb_free(exp);
    }
}
