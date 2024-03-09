/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_grep.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_record_accessor.h>


static int delete_rule(struct flb_grep_rule *rule)
{
    if (rule == NULL) {
        return -1;
    }

    if (rule->field) {
        flb_sds_destroy(rule->field);
    }
    if (rule->regex_pattern) {
        flb_free(rule->regex_pattern);
    }
    if (rule->ra) {
        flb_ra_destroy(rule->ra);
    }
    if (rule->regex) {
        flb_regex_destroy(rule->regex);
    }
    if (!mk_list_entry_is_orphan(&rule->_head)) {
        mk_list_del(&rule->_head);
    }
    flb_free(rule);

    return 0;
}

static int flb_grep_delete_rules(struct mk_list *rules)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_grep_rule *rule;

    if (rules == NULL) {
        return 0;
    }

    mk_list_foreach_safe(head, tmp, rules) {
        rule = mk_list_entry(head, struct flb_grep_rule, _head);
        delete_rule(rule);
    }
    return 0;
}

int flb_grep_destroy(struct flb_grep *grep_ctx)
{
    int ret;

    if (grep_ctx == NULL) {
        return 0;
    }

    ret = flb_grep_delete_rules(&grep_ctx->rules);
    flb_free(grep_ctx);

    return ret;
}


static int is_valid_rule_type(struct flb_grep *grep_ctx, enum flb_grep_rule_type type)
{
    if (type == FLB_GREP_NO_RULE) {
        flb_error("%s: invalid type", __FUNCTION__);
        return -1;
    }

    if (grep_ctx->op != FLB_GREP_LOGICAL_OP_LEGACY) {
        /* 'AND'/'OR' case */
        if (grep_ctx->first_rule != FLB_GREP_NO_RULE /* 2+ rules */ 
            && grep_ctx->first_rule != type) {
            flb_error("Both 'regex' and 'exclude' are set.");
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

/*
 * rule_str format is "KEY REGEX" .
 * e.g. hostname *.com
 */
int flb_grep_set_rule_str(struct flb_grep *grep_ctx, enum flb_grep_rule_type type, char *rule_str)
{
    int ret;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_grep_rule *rule = NULL;

    if (grep_ctx == NULL || rule_str == NULL) {
        flb_error("%s: input error", __FUNCTION__);
        return -1;
    }

    if (is_valid_rule_type(grep_ctx, type) != FLB_TRUE) {
        return -1;
    }

    rule = flb_calloc(1, sizeof(struct flb_grep_rule));
    if (rule == NULL) {
        flb_errno();
        return -1;
    }
    rule->type = type;
    if (grep_ctx->first_rule == FLB_GREP_NO_RULE) {
        grep_ctx->first_rule = type;
    }

    /* As a value we expect a pair of field name and a regular expression */
    split = flb_utils_split(rule_str, ' ', 1);
    if (mk_list_size(split) != 2) {
        flb_error("invalid regex, expected field and regular expression");
        delete_rule(rule);
        flb_utils_split_free(split);
        return -1;
    }
    /* Get first value (field) */
    sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
    if (sentry->value[0] == '$') {
        rule->field = flb_sds_create_len(sentry->value, sentry->len);
        if (rule->field == NULL) {
            flb_error("flb_sds_create_len failed");
            delete_rule(rule);
            flb_utils_split_free(split);
            return -1;
        }
    }
    else {
        rule->field = flb_sds_create_size(sentry->len + 2);
        if (rule->field == NULL) {
            flb_error("flb_sds_create_size failed");
            delete_rule(rule);
            flb_utils_split_free(split);
            return -1;
        }
        ret = flb_sds_snprintf(&rule->field, flb_sds_alloc(rule->field),
                               "$%.*s", (int)sentry->len, sentry->value);
        if (ret < 0 || ret >= sentry->len + 2) {
            flb_error("flb_sds_snprintf failed");
            delete_rule(rule);
            flb_utils_split_free(split);
            return -1;
        }
    }

    /* Get remaining content (regular expression) */
    sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
    rule->regex_pattern = flb_strndup(sentry->value, sentry->len);
    if (rule->regex_pattern == NULL) {
        flb_errno();
        delete_rule(rule);
        flb_utils_split_free(split);
        return -1;
    }

    /* Release split */
    flb_utils_split_free(split);

    /* Create a record accessor context for this rule */
    rule->ra = flb_ra_create(rule->field, FLB_FALSE);
    if (!rule->ra) {
        flb_error("invalid record accessor? '%s'", rule->field);
        delete_rule(rule);
        return -1;
    }

    /* Convert string to regex pattern */
    rule->regex = flb_regex_create(rule->regex_pattern);
    if (!rule->regex) {
        flb_error("could not compile regex pattern '%s'",
                  rule->regex_pattern);
        delete_rule(rule);
        return -1;
    }

    /* Link to parent list */
    mk_list_add(&rule->_head, &grep_ctx->rules);

    return 0;
}

struct flb_grep *flb_grep_create(enum flb_grep_logical_op op)
{
    struct flb_grep *ctx = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_grep));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->first_rule = FLB_GREP_NO_RULE;
    ctx->op = op;
    mk_list_init(&ctx->rules);

    return ctx;
}

static int flb_grep_filter_legacy(msgpack_object map,
                                  struct flb_grep *grep_ctx)
{
    ssize_t ret;
    struct mk_list *head;
    struct flb_grep_rule *rule;

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &grep_ctx->rules) {
        rule = mk_list_entry(head, struct flb_grep_rule, _head);

        ret = flb_ra_regex_match(rule->ra, map, rule->regex, NULL);
        if (ret <= 0) { /* no match */
            if (rule->type == FLB_GREP_REGEX) {
                return FLB_GREP_RET_EXCLUDE;
            }
        }
        else {
            if (rule->type == FLB_GREP_EXCLUDE) {
                return FLB_GREP_RET_EXCLUDE;
            }
            else {
                return FLB_GREP_RET_KEEP;
            }
        }
    }

    return FLB_GREP_RET_KEEP;
}

static int flb_grep_filter_data_and_or(msgpack_object map, struct flb_grep *ctx)
{
    ssize_t ra_ret;
    int found = FLB_FALSE;
    struct mk_list *head;
    struct flb_grep_rule *rule;

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &ctx->rules) {
        found = FLB_FALSE;
        rule = mk_list_entry(head, struct flb_grep_rule, _head);

        ra_ret = flb_ra_regex_match(rule->ra, map, rule->regex, NULL);
        if (ra_ret > 0) {
            found = FLB_TRUE;
        }

        if (ctx->op == FLB_GREP_LOGICAL_OP_OR && found == FLB_TRUE) {
            /* OR case: One rule is matched. */
            goto grep_filter_data_and_or_end;
        }
        else if (ctx->op == FLB_GREP_LOGICAL_OP_AND && found == FLB_FALSE) {
            /* AND case: One rule is not matched */
            goto grep_filter_data_and_or_end;
        }
    }

 grep_filter_data_and_or_end:
    if (rule->type == FLB_GREP_REGEX) {
        if (found) {
            return FLB_GREP_RET_KEEP;
        }
        return FLB_GREP_RET_EXCLUDE;
    }

    /* rule is exclude */
    if (found) {
        return FLB_GREP_RET_EXCLUDE;
    }
    return FLB_GREP_RET_KEEP;
}

int flb_grep_filter(msgpack_object map, struct flb_grep *grep_ctx)
{
    if (grep_ctx->op == FLB_GREP_LOGICAL_OP_LEGACY) {
        return flb_grep_filter_legacy(map, grep_ctx);
    }
    return flb_grep_filter_data_and_or(map, grep_ctx);
}
