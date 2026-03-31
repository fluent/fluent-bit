/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* Fluent Bit
 * ==========
 * Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FLB_CONDITIONS_H
#define FLB_CONDITIONS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_cfl_record_accessor.h>
#include <monkey/mk_core.h>
#include <fluent-bit/flb_mp_chunk.h>

struct flb_condition_rule;

typedef struct cfl_variant *(*flb_condition_get_variant_fn)(struct flb_condition_rule *rule,
                                                            void *ctx);

/* Context types enum */
enum record_context_type {
    RECORD_CONTEXT_BODY = 0,
    RECORD_CONTEXT_METADATA = 1,
    RECORD_CONTEXT_GROUP_METADATA,
    RECORD_CONTEXT_GROUP_ATTRIBUTES,
    RECORD_CONTEXT_OTEL_RESOURCE_ATTRIBUTES,
    RECORD_CONTEXT_OTEL_SCOPE_ATTRIBUTES,
    RECORD_CONTEXT_OTEL_SCOPE_METADATA
};

struct flb_condition;

enum flb_condition_operator {
    FLB_COND_OP_AND,
    FLB_COND_OP_OR
};

enum flb_rule_operator {
    FLB_RULE_OP_EQ,
    FLB_RULE_OP_NEQ,
    FLB_RULE_OP_GT,
    FLB_RULE_OP_LT,
    FLB_RULE_OP_GTE,
    FLB_RULE_OP_LTE,
    FLB_RULE_OP_REGEX,
    FLB_RULE_OP_NOT_REGEX,
    FLB_RULE_OP_IN,
    FLB_RULE_OP_NOT_IN
};

struct flb_condition_rule {
    struct flb_cfl_record_accessor *ra;  /* Record accessor for the field */
    enum record_context_type context;    /* Whether rule applies to body or metadata */
    enum flb_rule_operator op;
    union {
        flb_sds_t str_val;
        double num_val;
        struct {
            flb_sds_t *values;
            int count;
        } array;
    } value;
    struct flb_regex *regex;
    struct mk_list _head;
};

struct flb_condition {
    enum flb_condition_operator op;
    struct mk_list rules;
};

/* Core condition functions */
struct flb_condition *flb_condition_create(enum flb_condition_operator op);

int flb_condition_add_rule(struct flb_condition *cond,
                          const char *field,
                          enum flb_rule_operator op,
                          void *value,
                          int value_count,
                          enum record_context_type context);

void flb_condition_destroy(struct flb_condition *cond);

/* Evaluation function */
int flb_condition_evaluate_ex(struct flb_condition *cond,
                             void *ctx,
                             flb_condition_get_variant_fn get_variant);
int flb_condition_evaluate(struct flb_condition *cond,
                          struct flb_mp_chunk_record *record);

#endif /* FLB_CONDITIONS_H */