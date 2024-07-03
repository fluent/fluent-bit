/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

#include "processor-sql_parser.h"
#include "processor-sql-parser_lex.h"

#include "sql.h"

int sql_parser_query_key_add(struct sql_query *query, char *key_name, char *key_alias)
{
    struct sql_key *key;

    key = flb_calloc(1, sizeof(struct sql_key));
    if (!key) {
        flb_errno();
        return -1;
    }

    if (key_name) {
        key->name = flb_sds_create(key_name);
        if (!key->name) {
            flb_free(key);
            return -1;
        }
    }
    else {
        /* wildcard case */
        if (cfl_list_size(&query->keys) > 0) {
            cfl_sds_destroy(key->name);
            flb_free(key);
            return -1;
        }
    }

    if (key_alias) {
        key->alias = flb_sds_create(key_alias);
        if (!key->alias) {
            flb_sds_destroy(key->name);
            flb_free(key);
            return -1;
        }
    }

    cfl_list_add(&key->_head, &query->keys);
    return 0;
}

static void condition_list_delete(struct cfl_list *cond_list)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct sql_expression *exp;
    struct sql_expression_key *exp_key;
    struct sql_expression_val *exp_val;

    /* conditions */
    cfl_list_foreach_safe(head, tmp, cond_list) {
        exp = cfl_list_entry(head, struct sql_expression, _head);
        if (exp->type == SQL_EXP_KEY) {
            exp_key = (struct sql_expression_key *) exp;
            cfl_sds_destroy(exp_key->name);
        }
        else if (exp->type == SQL_EXP_STRING) {
            exp_val = (struct sql_expression_val *) exp;
            cfl_sds_destroy(exp_val->val.string);
        }
        /* note: SQL_EXP_NULL is released directly */

        cfl_list_del(&exp->_head);
        flb_free(exp);
    }
}

static void keys_list_delete(struct cfl_list *keys)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct sql_key *key;

    cfl_list_foreach_safe(head, tmp, keys) {
        key = cfl_list_entry(head, struct sql_key, _head);
        cfl_sds_destroy(key->name);
        if (key->alias) {
            cfl_sds_destroy(key->alias);
        }
        cfl_list_del(&key->_head);
        flb_free(key);
    }
}

void sql_parser_query_destroy(struct sql_query *query)
{
    /* delete keys list items */
    keys_list_delete(&query->keys);

    /* delete condition list items */
    condition_list_delete(&query->cond_list);
    flb_free(query);
}

struct sql_query *sql_parser_query_create(cfl_sds_t query_str)
{
    int ret;
    yyscan_t scanner;
    YY_BUFFER_STATE buf;
    struct sql_query *query;

    query = flb_calloc(1, sizeof(struct sql_query));
    if (!query) {
        flb_errno();
        return NULL;
    }
    cfl_list_init(&query->keys);
    cfl_list_init(&query->cond_list);

     /* Flex/Bison work */
    yylex_init(&scanner);
    buf = yy_scan_string(query_str, scanner);

    ret = yyparse(query, scanner);
    if (ret != 0) {
        sql_parser_query_destroy(query);
        return NULL;
    }

    yy_delete_buffer(buf, scanner);
    yylex_destroy(scanner);

    return query;
}
