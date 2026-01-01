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

#ifndef FLB_PROCESSOR_SQL_EXPRESSION_H
#define FLB_PROCESSOR_SQL_EXPRESSION_H

#include <fluent-bit/flb_processor_plugin.h>
#include "sql.h"

struct sql_expression *sql_expression_operation(struct sql_query *query,
                                                struct sql_expression *e1,
                                                struct sql_expression *e2,
                                                int operation);

void sql_expression_condition_add(struct sql_query *query, struct sql_expression *e);

struct sql_expression *sql_expression_condition_key(struct sql_query *query,
                                                    const char *identifier);

struct sql_expression *sql_expression_condition_integer(struct sql_query *query,
                                                        int integer);

struct sql_expression *sql_expression_condition_float(struct sql_query *query,
                                                      float fval);

struct sql_expression *sql_expression_condition_string(struct sql_query *query,
                                                       const char *string);

struct sql_expression *sql_expression_condition_boolean(struct sql_query *query,
                                                        int boolean);

struct sql_expression *sql_expression_condition_null(struct sql_query *query);

struct sql_expression *sql_expression_comparison(struct sql_query *query,
                                                 struct sql_expression *key,
                                                 struct sql_expression *val,
                                                 int operation);


#endif
