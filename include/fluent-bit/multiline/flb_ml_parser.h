/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#ifndef FLB_ML_PARSER_H
#define FLB_ML_PARSER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>

int flb_ml_parser_init(struct flb_ml_parser *ml_parser);

int flb_ml_parser_builtin_create(struct flb_config *config);

struct flb_ml_parser *flb_ml_parser_create(struct flb_config *ctx,
                                           char *name,
                                           int type, char *match_str, int negate,
                                           int flush_ms,
                                           char *key_content,
                                           char *key_group,
                                           char *key_pattern,
                                           struct flb_parser *parser_ctx,
                                           char *parser_name);
int flb_ml_parser_destroy(struct flb_ml_parser *ml_parser);
void flb_ml_parser_destroy_all(struct mk_list *list);

struct flb_ml_parser *flb_ml_parser_get(struct flb_config *ctx, char *name);

struct flb_ml_parser_ins *flb_ml_parser_instance_create(struct flb_ml *ml,
                                                        char *name);
int flb_ml_parser_instance_set(struct flb_ml_parser_ins *p, char *prop, char *val);

int flb_ml_parser_instance_destroy(struct flb_ml_parser_ins *ins);
int flb_ml_parser_instance_has_data(struct flb_ml_parser_ins *ins);

/* Built-in multiline parsers */
struct flb_ml_parser *flb_ml_parser_docker(struct flb_config *config);
struct flb_ml_parser *flb_ml_parser_cri(struct flb_config *config);
struct flb_ml_parser *flb_ml_parser_java(struct flb_config *config, char *key);
struct flb_ml_parser *flb_ml_parser_go(struct flb_config *config, char *key);
struct flb_ml_parser *flb_ml_parser_ruby(struct flb_config *config, char *key);
struct flb_ml_parser *flb_ml_parser_python(struct flb_config *config, char *key);

#endif
