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

#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include "grep.h"

static void delete_rules(struct grep_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct grep_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);
        flb_sds_destroy(rule->field);
        flb_free(rule->regex_pattern);
        flb_ra_destroy(rule->ra);
        flb_regex_destroy(rule->regex);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static int set_rules(struct grep_ctx *ctx, struct flb_filter_instance *f_ins)
{
    int first_rule = GREP_NO_RULE;
    flb_sds_t tmp;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_kv *kv;
    struct grep_rule *rule;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Create a new rule */
        rule = flb_malloc(sizeof(struct grep_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }

        /* Get the type */
        if (strcasecmp(kv->key, "regex") == 0) {
            rule->type = GREP_REGEX;
        }
        else if (strcasecmp(kv->key, "exclude") == 0) {
            rule->type = GREP_EXCLUDE;
        }
        else {
            /* Other property. Skip */
            flb_free(rule);
            continue;
        }

        if (ctx->logical_op != GREP_LOGICAL_OP_LEGACY && first_rule != GREP_NO_RULE) {
            /* 'AND'/'OR' case */
            if (first_rule != rule->type) {
                flb_plg_error(ctx->ins, "Both 'regex' and 'exclude' are set.");
                delete_rules(ctx);
                flb_free(rule);
                return -1;
            }
        }
        first_rule = rule->type;

        /* As a value we expect a pair of field name and a regular expression */
        split = flb_utils_split(kv->val, ' ', 1);
        if (mk_list_size(split) != 2) {
            flb_plg_error(ctx->ins,
                          "invalid regex, expected field and regular expression");
            delete_rules(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        if (*sentry->value == '$') {
            rule->field = flb_sds_create_len(sentry->value, sentry->len);
        }
        else {
            rule->field = flb_sds_create_size(sentry->len + 2);
            tmp = flb_sds_cat(rule->field, "$", 1);
            rule->field = tmp;

            tmp = flb_sds_cat(rule->field, sentry->value, sentry->len);
            rule->field = tmp;
        }

        /* Get remaining content (regular expression) */
        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        rule->regex_pattern = flb_strndup(sentry->value, sentry->len);
        if (rule->regex_pattern == NULL) {
            flb_errno();
            delete_rules(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Release split */
        flb_utils_split_free(split);

        /* Create a record accessor context for this rule */
        rule->ra = flb_ra_create(rule->field, FLB_FALSE);
        if (!rule->ra) {
            flb_plg_error(ctx->ins, "invalid record accessor? '%s'", rule->field);
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* Convert string to regex pattern */
        rule->regex = flb_regex_create(rule->regex_pattern);
        if (!rule->regex) {
            flb_plg_error(ctx->ins, "could not compile regex pattern '%s'",
                      rule->regex_pattern);
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* Link to parent list */
        mk_list_add(&rule->_head, &ctx->rules);
    }

    return 0;
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int grep_filter_data(msgpack_object map, struct grep_ctx *ctx)
{
    ssize_t ret;
    struct mk_list *head;
    struct grep_rule *rule;

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);

        ret = flb_ra_regex_match(rule->ra, map, rule->regex, NULL);
        if (ret <= 0) { /* no match */
            if (rule->type == GREP_REGEX) {
                return GREP_RET_EXCLUDE;
            }
        }
        else {
            if (rule->type == GREP_EXCLUDE) {
                return GREP_RET_EXCLUDE;
            }
            else {
                return GREP_RET_KEEP;
            }
        }
    }

    return GREP_RET_KEEP;
}

static int cb_grep_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    size_t len;
    const char* val;
    struct grep_ctx *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct grep_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }
    mk_list_init(&ctx->rules);
    ctx->ins = f_ins;

    ctx->logical_op = GREP_LOGICAL_OP_LEGACY;
    val = flb_filter_get_property("logical_op", f_ins);
    if (val != NULL) {
        len = strlen(val);
        if (len == 3 && strncasecmp("AND", val, len) == 0) {
            flb_plg_info(ctx->ins, "AND mode");
            ctx->logical_op = GREP_LOGICAL_OP_AND;
        }
        else if (len == 2 && strncasecmp("OR", val, len) == 0) {
            flb_plg_info(ctx->ins, "OR mode");
            ctx->logical_op = GREP_LOGICAL_OP_OR;
        }
        else if (len == 6 && strncasecmp("legacy", val, len) == 0) {
            flb_plg_info(ctx->ins, "legacy mode");
            ctx->logical_op = GREP_LOGICAL_OP_LEGACY;
        }
    }

    /* Load rules */
    ret = set_rules(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static inline int grep_filter_data_and_or(msgpack_object map, struct grep_ctx *ctx)
{
    ssize_t ra_ret;
    int found = FLB_FALSE;
    struct mk_list *head;
    struct grep_rule *rule;

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &ctx->rules) {
        found = FLB_FALSE;
        rule = mk_list_entry(head, struct grep_rule, _head);

        ra_ret = flb_ra_regex_match(rule->ra, map, rule->regex, NULL);
        if (ra_ret > 0) {
            found = FLB_TRUE;
        }

        if (ctx->logical_op == GREP_LOGICAL_OP_OR && found == FLB_TRUE) {
            /* OR case: One rule is matched. */
            goto grep_filter_data_and_or_end;
        }
        else if (ctx->logical_op == GREP_LOGICAL_OP_AND && found == FLB_FALSE) {
            /* AND case: One rule is not matched */
            goto grep_filter_data_and_or_end;
        }
    }

 grep_filter_data_and_or_end:
    if (rule->type == GREP_REGEX) {
        return found ? GREP_RET_KEEP : GREP_RET_EXCLUDE;
    }

    /* rule is exclude */
    return found ? GREP_RET_EXCLUDE : GREP_RET_KEEP;
}

static int cb_grep_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t *out_size,
                          struct flb_filter_instance *f_ins,
                          struct flb_input_instance *i_ins,
                          void *context,
                          struct flb_config *config)
{
    int ret;
    int old_size = 0;
    int new_size = 0;
    msgpack_object map;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct grep_ctx *ctx;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    ctx = (struct grep_ctx *) context;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        old_size++;

        /* get time and map */
        map  = *log_event.body;

        if (ctx->logical_op == GREP_LOGICAL_OP_LEGACY) {
            ret = grep_filter_data(map, ctx);
        }
        else {
            ret = grep_filter_data_and_or(map, ctx);
        }

        if (ret == GREP_RET_KEEP) {
            ret = flb_log_event_encoder_emit_raw_record(
                             &log_encoder,
                             log_decoder.record_base,
                             log_decoder.record_length);

            new_size++;
        }
        else if (ret == GREP_RET_EXCLUDE) {
            /* Do nothing */
        }
    }

    if (ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA &&
        log_decoder.offset == bytes) {
        ret = FLB_EVENT_ENCODER_SUCCESS;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* we keep everything ? */
    if (old_size == new_size) {
        flb_log_event_encoder_destroy(&log_encoder);

        /* Destroy the buffer to avoid more overhead */
        return FLB_FILTER_NOTOUCH;
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        *out_buf  = log_encoder.output_buffer;
        *out_size = log_encoder.output_length;

        ret = FLB_FILTER_MODIFIED;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
    }
    else {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %d", ret);

        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static int cb_grep_exit(void *data, struct flb_config *config)
{
    struct grep_ctx *ctx = data;

    if (!ctx) {
        return 0;
    }

    delete_rules(ctx);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "regex", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Keep records in which the content of KEY matches the regular expression."
    },
    {
     FLB_CONFIG_MAP_STR, "exclude", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Exclude records in which the content of KEY matches the regular expression."
    },
    {
     FLB_CONFIG_MAP_STR, "logical_op", "legacy",
     0, FLB_FALSE, 0,
     "Specify whether to use logical conjuciton or disjunction. legacy, AND and OR are allowed."
    },
    {0}
};

struct flb_filter_plugin filter_grep_plugin = {
    .name         = "grep",
    .description  = "grep events by specified field values",
    .cb_init      = cb_grep_init,
    .cb_filter    = cb_grep_filter,
    .cb_exit      = cb_grep_exit,
    .config_map   = config_map,
    .flags        = 0
};
