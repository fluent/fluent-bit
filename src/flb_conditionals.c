/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* Fluent Bit
 * ==========
 * Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_conditionals.h>

/* Function to get the record variant based on context */
static inline struct cfl_variant *get_record_variant(struct flb_mp_chunk_record *record,
                                                    enum record_context_type context_type)
{
    if (!record) {
        return NULL;
    }

    switch (context_type) {
    case RECORD_CONTEXT_METADATA:
        if (record->cobj_metadata) {
            return record->cobj_metadata->variant;
        }
        break;

    case RECORD_CONTEXT_BODY:
        if (record->cobj_record) {
            return record->cobj_record->variant;
        }
        break;
    }

    return NULL;
}

static struct flb_condition_rule *rule_create(const char *field,
                                             enum flb_rule_operator op,
                                             void *value,
                                             int value_count,
                                             enum record_context_type context)
{
    struct flb_condition_rule *rule;
    int i,j;

    if (!field || !value) {
        return NULL;
    }

    switch (op) {
    case FLB_RULE_OP_EQ:
    case FLB_RULE_OP_NEQ:
    case FLB_RULE_OP_REGEX:
    case FLB_RULE_OP_NOT_REGEX:
        if (!value || !((char *)value)[0]) {
            return NULL;
        }
        break;
    case FLB_RULE_OP_GT:
    case FLB_RULE_OP_LT:
    case FLB_RULE_OP_GTE:
    case FLB_RULE_OP_LTE:
        if (!value) {
            return NULL;
        }
        break;

    case FLB_RULE_OP_IN:
    case FLB_RULE_OP_NOT_IN:
        if (!value || value_count <= 0 || !((char **)value)[0]) {
            return NULL;
        }
        for (i = 0; i < value_count; i++) {
            if (!((char **)value)[i]) {
                return NULL;
            }
        }
        break;

    default:
        return NULL;
    }

    rule = flb_calloc(1, sizeof(struct flb_condition_rule));
    if (!rule) {
        cfl_errno();
        return NULL;
    }

    rule->ra = flb_cfl_ra_create((char *)field, FLB_TRUE);
    if (!rule->ra) {
        flb_free(rule);
        return NULL;
    }

    rule->context = context;
    rule->op = op;

    switch (op) {
    case FLB_RULE_OP_NEQ:
    case FLB_RULE_OP_EQ:
        rule->value.str_val = flb_sds_create((char *)value);
        if (!rule->value.str_val) {
            flb_cfl_ra_destroy(rule->ra);
            flb_free(rule);
            return NULL;
        }
        break;

    case FLB_RULE_OP_GT:
    case FLB_RULE_OP_LT:
    case FLB_RULE_OP_GTE:
    case FLB_RULE_OP_LTE:
        rule->value.num_val = *(double *)value;
        break;

    case FLB_RULE_OP_REGEX:
    case FLB_RULE_OP_NOT_REGEX:
        rule->regex = flb_regex_create((char *)value);
        if (!rule->regex) {
            flb_cfl_ra_destroy(rule->ra);
            flb_free(rule);
            return NULL;
        }
        break;

    case FLB_RULE_OP_IN:
    case FLB_RULE_OP_NOT_IN:
        rule->value.array.values = flb_calloc(value_count, sizeof(flb_sds_t));
        if (!rule->value.array.values) {
            flb_cfl_ra_destroy(rule->ra);
            flb_free(rule);
            return NULL;
        }

        for (i = 0; i < value_count; i++) {
            rule->value.array.values[i] = flb_sds_create(((char **)value)[i]);
            if (!rule->value.array.values[i]) {
                for (j = 0; j < i; j++) {
                    flb_sds_destroy(rule->value.array.values[j]);
                }
                flb_free(rule->value.array.values);
                flb_cfl_ra_destroy(rule->ra);
                flb_free(rule);
                return NULL;
            }
        }
        rule->value.array.count = value_count;
        break;
    }

    return rule;
}

static void rule_destroy(struct flb_condition_rule *rule)
{
    int i;

    if (!rule) {
        return;
    }

    if (rule->ra) {
        flb_cfl_ra_destroy(rule->ra);
    }

    switch (rule->op) {
    case FLB_RULE_OP_EQ:
    case FLB_RULE_OP_NEQ:
        if (rule->value.str_val) {
            flb_sds_destroy(rule->value.str_val);
        }
        break;

    case FLB_RULE_OP_REGEX:
    case FLB_RULE_OP_NOT_REGEX:
        if (rule->regex) {
            flb_regex_destroy(rule->regex);
        }
        break;

    case FLB_RULE_OP_IN:
    case FLB_RULE_OP_NOT_IN:
        for (i = 0; i < rule->value.array.count; i++) {
            flb_sds_destroy(rule->value.array.values[i]);
        }
        flb_free(rule->value.array.values);
        break;

    case FLB_RULE_OP_GT:
    case FLB_RULE_OP_LT:
    case FLB_RULE_OP_GTE:
    case FLB_RULE_OP_LTE:
        break;

    default:
        break;
    }

    flb_free(rule);
}

struct flb_condition *flb_condition_create(enum flb_condition_operator op)
{
    struct flb_condition *cond;

    cond = flb_calloc(1, sizeof(struct flb_condition));
    if (!cond) {
        cfl_errno();
        return NULL;
    }

    cond->op = op;
    mk_list_init(&cond->rules);

    return cond;
}

int flb_condition_add_rule(struct flb_condition *cond,
                           const char *field,
                           enum flb_rule_operator op,
                           void *value,
                           int value_count,
                           enum record_context_type context)
{
    struct flb_condition_rule *rule;

    if (!cond || !field || !value) {
        return FLB_FALSE;
    }

    rule = rule_create(field, op, value, value_count, context);
    if (!rule) {
        return FLB_FALSE;
    }

    mk_list_add(&rule->_head, &cond->rules);
    return FLB_TRUE;
}

void flb_condition_destroy(struct flb_condition *cond)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_condition_rule *rule;

    if (!cond) {
        return;
    }

    mk_list_foreach_safe(head, tmp, &cond->rules) {
        rule = mk_list_entry(head, struct flb_condition_rule, _head);
        mk_list_del(&rule->_head);
        rule_destroy(rule);
    }

    flb_free(cond);
}

static int evaluate_rule(struct flb_condition_rule *rule,
                         struct cfl_variant *record_variant)
{
    flb_sds_t str_val;
    int i;
    int result = FLB_FALSE;
    double num_val;

    if (!rule || !record_variant) {
        flb_trace("[condition] evaluate_rule: NULL rule or record variant");
        return FLB_FALSE;
    }

    flb_trace("[condition] evaluating rule with record accessor");
    str_val = flb_cfl_ra_translate(rule->ra, NULL, 0, *record_variant, NULL);
    if (!str_val) {
        flb_trace("[condition] record accessor translation failed");
        return FLB_FALSE;
    }

    flb_trace("[condition] record accessor returned value: '%s'", str_val);

    switch (rule->op) {
    case FLB_RULE_OP_EQ:
        flb_trace("[condition] EQ comparison: '%s' == '%s'", str_val, rule->value.str_val);
        result = (strcmp(str_val, rule->value.str_val) == 0);
        break;

    case FLB_RULE_OP_NEQ:
        flb_trace("[condition] NEQ comparison: '%s' != '%s'", str_val, rule->value.str_val);
        result = (strcmp(str_val, rule->value.str_val) != 0);
        break;

    case FLB_RULE_OP_GT:
        num_val = atof(str_val);
        result = (num_val > rule->value.num_val);
        break;

    case FLB_RULE_OP_LT:
        num_val = atof(str_val);
        result = (num_val < rule->value.num_val);
        break;

    case FLB_RULE_OP_GTE:
        num_val = atof(str_val);
        result = (num_val >= rule->value.num_val);
        break;

    case FLB_RULE_OP_LTE:
        num_val = atof(str_val);
        result = (num_val <= rule->value.num_val);
        break;

    case FLB_RULE_OP_REGEX:
        result = (flb_regex_match(rule->regex,
                                  (unsigned char *)str_val,
                                  flb_sds_len(str_val)) > 0);
        break;

    case FLB_RULE_OP_NOT_REGEX:
        result = (flb_regex_match(rule->regex,
                                  (unsigned char *)str_val,
                                  flb_sds_len(str_val)) <= 0);
        break;

    case FLB_RULE_OP_IN:
    case FLB_RULE_OP_NOT_IN:
        for (i = 0; i < rule->value.array.count; i++) {
            if (strcmp(str_val, rule->value.array.values[i]) == 0) {
                result = (rule->op == FLB_RULE_OP_IN);
                break;
            }
        }
        if (i == rule->value.array.count) {
            result = (rule->op == FLB_RULE_OP_NOT_IN);
        }
        break;
    }

    flb_sds_destroy(str_val);
    return result;
}

int flb_condition_evaluate(struct flb_condition *cond,
                           struct flb_mp_chunk_record *record)
{
    struct mk_list *head;
    struct flb_condition_rule *rule;
    struct cfl_variant *record_variant;
    int result;

    if (!cond || !record) {
        flb_trace("[condition] NULL condition or record, returning TRUE");
        return FLB_TRUE;
    }

    flb_trace("[condition] evaluating condition with %d rules", mk_list_size(&cond->rules));

    if (mk_list_size(&cond->rules) == 0) {
        flb_trace("[condition] empty rule set, returning default result");
        return (cond->op == FLB_COND_OP_AND);
    }

    mk_list_foreach(head, &cond->rules) {
        rule = mk_list_entry(head, struct flb_condition_rule, _head);
        flb_trace("[condition] processing rule with op=%d", rule->op);

        /* Get the variant for this rule's context */
        record_variant = get_record_variant(record, rule->context);
        if (!record_variant) {
            flb_trace("[condition] no record variant found for context %d", rule->context);
            continue;
        }

        flb_trace("[condition] evaluating rule against record");
        result = evaluate_rule(rule, record_variant);
        flb_trace("[condition] rule evaluation result: %d", result);

        if (cond->op == FLB_COND_OP_AND && result == FLB_FALSE) {
            flb_trace("[condition] AND condition with FALSE result, short-circuiting");
            return FLB_FALSE;
        }
        else if (cond->op == FLB_COND_OP_OR && result == FLB_TRUE) {
            flb_trace("[condition] OR condition with TRUE result, short-circuiting");
            return FLB_TRUE;
        }
    }

    flb_trace("[condition] final evaluation result: %d", (cond->op == FLB_COND_OP_AND) ? FLB_TRUE : FLB_FALSE);
    return (cond->op == FLB_COND_OP_AND) ? FLB_TRUE : FLB_FALSE;
}