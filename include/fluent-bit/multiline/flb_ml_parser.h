/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

/* fwd decl */
struct flb_config;

/*
 * Size based parameter bag for creating multiline parsers.
 * - Call flb_ml_parser_params_default(name) to obtain defaults,
 *   then tweak only the fields you need before passing to v2.
 */
struct flb_ml_parser_params {
    uint16_t size;      /* sizeof(struct flb_ml_parser_params) */

    /* creation parameters (mirror of old positional args) */
    char *name;
    int   type;         /* FLB_ML_REGEX / FLB_ML_ENDSWITH / FLB_ML_EQ */
    char *match_str;    /* used for ENDSWITH/EQ; NULL for REGEX */
    int   negate;       /* 0/1 */
    int   flush_ms;     /* default: FLB_ML_FLUSH_TIMEOUT */
    char *key_content;
    char *key_group;
    char *key_pattern;
    struct flb_parser *parser_ctx; /* immediate */
    char *parser_name;             /* delayed init */

    /* for future toggles */
    uint32_t flags;
};

/* Fill sane defaults */
struct flb_ml_parser_params flb_ml_parser_params_default(const char *name);

/* New initializer with params */
struct flb_ml_parser *flb_ml_parser_create_params(struct flb_config *ctx,
                                                  const struct flb_ml_parser_params *p);

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
