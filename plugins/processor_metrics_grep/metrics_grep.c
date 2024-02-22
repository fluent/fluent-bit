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

#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_metrics.h>
#include <msgpack.h>

#include "metrics_grep.h"

static void delete_metrics_rules(struct metrics_grep_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct metrics_grep_rule *metrics_rule;

    mk_list_foreach_safe(head, tmp, &ctx->metrics_rules) {
        metrics_rule = mk_list_entry(head, struct metrics_grep_rule, _head);
        flb_free(metrics_rule->regex_pattern);
        flb_regex_destroy(metrics_rule->regex);
        mk_list_del(&metrics_rule->_head);
        flb_free(metrics_rule);
    }
}

static void destroy_context(struct metrics_grep_ctx *context)
{
    if (context != NULL) {
        delete_metrics_rules(context);
        flb_free(context);
    }
}

static int set_metrics_rules(struct metrics_grep_ctx *ctx, struct flb_processor_instance *p_ins)
{
    int first_rule = METRICS_GREP_NO_RULE;
    struct mk_list *head;
    struct flb_kv *kv;
    struct metrics_grep_rule *metrics_rule;

    /* Iterate all filter properties for metrics.regex and metrics.exclude */
    mk_list_foreach(head, &p_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Create a new rule */
        metrics_rule = flb_malloc(sizeof(struct metrics_grep_rule));
        if (!metrics_rule) {
            flb_errno();
            return -1;
        }

        /* Get the type */
        if (strncasecmp(kv->key, "metrics.regex", 13) == 0) {
            metrics_rule->type = METRICS_GREP_REGEX;
        }
        else if (strncasecmp(kv->key, "metrics.exclude", 15) == 0) {
            metrics_rule->type = METRICS_GREP_EXCLUDE;
        }
        else {
            /* Other property. Skip */
            flb_free(metrics_rule);
            continue;
        }

        if (ctx->logical_op != METRICS_GREP_LOGICAL_OP_LEGACY && first_rule != METRICS_GREP_NO_RULE) {
            /* 'AND'/'OR' case */
            if (first_rule != metrics_rule->type) {
                flb_plg_error(ctx->ins, "Both 'metrics.regex' and 'metrics.exclude' are set.");
                delete_metrics_rules(ctx);
                flb_free(metrics_rule);
                return -1;
            }
        }
        first_rule = metrics_rule->type;

        /* Get name (regular expression) */
        metrics_rule->regex_pattern = flb_strndup(kv->val, strlen(kv->val));
        if (metrics_rule->regex_pattern == NULL) {
            flb_errno();
            delete_metrics_rules(ctx);
            flb_free(metrics_rule);
            return -1;
        }

        /* Convert string to regex pattern for metrics */
        metrics_rule->regex = flb_regex_create(metrics_rule->regex_pattern);
        if (!metrics_rule->regex) {
            flb_plg_error(ctx->ins, "could not compile regex pattern '%s'",
                          metrics_rule->regex_pattern);
            delete_metrics_rules(ctx);
            flb_free(metrics_rule);
            return -1;
        }

        /* Link to parent list */
        mk_list_add(&metrics_rule->_head, &ctx->metrics_rules);
    }

    return 0;
}

static struct metrics_grep_ctx *
        create_context(struct flb_processor_instance *processor_instance,
                       struct flb_config *config)
{
    int ret;
    int result;
    size_t len;
    const char *val;
    struct metrics_grep_ctx *ctx;

    ctx = flb_malloc(sizeof(struct metrics_grep_ctx));
    if (ctx != NULL) {
        ctx->ins = processor_instance;
        ctx->config = config;

        mk_list_init(&ctx->metrics_rules);

        result = flb_processor_instance_config_map_set(processor_instance, (void *) ctx);

        if (result == 0) {
            ctx->logical_op = METRICS_GREP_LOGICAL_OP_LEGACY;
            val = flb_processor_instance_get_property("logical_op", processor_instance);
            if (val != NULL) {
                len = strlen(val);
                if (len == 3 && strncasecmp("AND", val, len) == 0) {
                    flb_plg_info(ctx->ins, "AND mode");
                    ctx->logical_op = METRICS_GREP_LOGICAL_OP_AND;
                }
                else if (len == 2 && strncasecmp("OR", val, len) == 0) {
                    flb_plg_info(ctx->ins, "OR mode");
                    ctx->logical_op = METRICS_GREP_LOGICAL_OP_OR;
                }
                else if (len == 6 && strncasecmp("legacy", val, len) == 0) {
                    flb_plg_info(ctx->ins, "legacy mode");
                    ctx->logical_op = METRICS_GREP_LOGICAL_OP_LEGACY;
                }
            }
        }

        if (result == 0) {
            /* Load rules */
            ret = set_metrics_rules(ctx, processor_instance);
            if (ret == -1) {
                destroy_context(ctx);
                ctx = NULL;

                return ctx;
            }
        }

        if (result != 0) {
            destroy_context(ctx);

            ctx = NULL;
        }
    }
    else {
        flb_errno();
    }

    return ctx;
}


static int cb_process_metrics_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    /* Create context */
    processor_instance->context = (void *) create_context(
                                            processor_instance, config);

    if (processor_instance->context == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

#ifdef FLB_HAVE_METRICS
static int cmt_regex_match(void *ctx, const char *str, size_t slen)
{
    int ret;
    struct flb_regex *r = (struct flb_regex *)ctx;
    unsigned char *s = (unsigned char*)str;
    ret = flb_regex_match(r, s, slen);

    if (ret == 1) {
        ret = CMT_TRUE;
    }
    else {
        ret = CMT_FALSE;
    }

    return ret;
}

static int cmt_regex_exclude(void *ctx, const char *str, size_t slen)
{
    int ret;
    struct flb_regex *r = (struct flb_regex *)ctx;
    unsigned char *s = (unsigned char*)str;
    ret = flb_regex_match(r, s, slen);

    if (ret == 1) {
        ret = CMT_FALSE;
    }
    else {
        ret = CMT_TRUE;
    }

    return ret;
}

static inline int grep_filter_metrics_or_op(struct cmt *cmt, struct cmt *out_cmt, struct metrics_grep_ctx *ctx)
{
    ssize_t ret;
    int found = FLB_FALSE;
    struct mk_list *head;
    struct metrics_grep_rule *metrics_rule;
    struct cmt *tmp = NULL;
    struct cmt *filtered = NULL;

    /* For each rule, validate against cmt context */
    mk_list_foreach(head, &ctx->metrics_rules) {
        found = FLB_FALSE;
        metrics_rule = mk_list_entry(head, struct metrics_grep_rule, _head);

        tmp = cmt_create();
        if (tmp == NULL) {
            flb_plg_error(ctx->ins, "could not create tmp context");
            return METRICS_GREP_FAILURE;
        }
        cmt_cat(tmp, cmt);
        filtered = cmt_create();
        if (filtered == NULL) {
            flb_plg_error(ctx->ins, "could not create filtered context");
            return METRICS_GREP_FAILURE;
        }

        if (metrics_rule->type == METRICS_GREP_REGEX) {
            ret = cmt_filter(filtered, tmp, NULL, NULL, metrics_rule->regex, cmt_regex_match, 0);
        }
        else if (metrics_rule->type == METRICS_GREP_EXCLUDE){
            ret = cmt_filter(filtered, tmp, NULL, NULL, metrics_rule->regex, cmt_regex_exclude, 0);
        }
        if (ret == 0) {
            found = FLB_TRUE;
        }

        if (found == FLB_TRUE) {
            cmt_cat(out_cmt, filtered);
        }
        cmt_destroy(tmp);
        cmt_destroy(filtered);
    }

    if (metrics_rule->type == METRICS_GREP_REGEX) {
        return found ? METRICS_GREP_RET_KEEP : METRICS_GREP_RET_EXCLUDE;
    }

    /* The last rule is exclude */
    return found ? METRICS_GREP_RET_EXCLUDE : METRICS_GREP_RET_KEEP;
}


static inline int grep_filter_metrics_and_op(struct cmt *cmt, struct cmt *out_cmt,
                                             struct metrics_grep_ctx *ctx)
{
    int ret;
    int found = FLB_FALSE;
    struct mk_list *head;
    struct metrics_grep_rule *metrics_rule;
    struct cmt *tmp = NULL;
    struct cmt *swap = NULL;
    struct cmt *filtered = NULL;
    size_t rule_size;
    int count = 1;
    rule_size = mk_list_size(&ctx->metrics_rules);

    /* For each rule, validate against cmt context */
    mk_list_foreach(head, &ctx->metrics_rules) {
        found = FLB_FALSE;
        metrics_rule = mk_list_entry(head, struct metrics_grep_rule, _head);
        if (tmp == NULL) {
            tmp = cmt_create();
            if (tmp == NULL) {
                flb_plg_error(ctx->ins, "could not create tmp context");
                return METRICS_GREP_FAILURE;
            }
            cmt_cat(tmp, cmt);
        }
        filtered = cmt_create();
        if (filtered == NULL) {
            flb_plg_error(ctx->ins, "could not create filtered context");
            cmt_destroy(tmp);

            return METRICS_GREP_FAILURE;
        }

        if (metrics_rule->type == METRICS_GREP_REGEX) {
            ret = cmt_filter(filtered, tmp, NULL, NULL, metrics_rule->regex, cmt_regex_match, 0);
        }
        else if (metrics_rule->type == METRICS_GREP_EXCLUDE){
            ret = cmt_filter(filtered, tmp, NULL, NULL, metrics_rule->regex, cmt_regex_exclude, 0);
        }

        if (ret == 0) {
            found = FLB_TRUE;
        }
        else if (ret != 0) {
            flb_plg_debug(ctx->ins, "not matched for rule = \"%s\"", metrics_rule->regex_pattern);
        }

        if (count >= rule_size) {
            if (swap != NULL) {
                cmt_destroy(swap);
            }
            cmt_cat(out_cmt, filtered);
            cmt_destroy(filtered);

            goto grep_filter_metrics_and_or_end;
        }

        if (filtered != NULL && tmp != NULL) {
            if (swap != NULL) {
                cmt_destroy(swap);
            }
            swap = cmt_create();
            if (swap == NULL) {
                flb_plg_error(ctx->ins, "could not create swap context");
                return METRICS_GREP_FAILURE;
            }
            cmt_cat(swap, filtered);
            cmt_destroy(tmp);
            cmt_destroy(filtered);
            tmp = NULL;
            tmp = swap;
        }
        count++;
    }

 grep_filter_metrics_and_or_end:

    if (metrics_rule->type == METRICS_GREP_REGEX) {
        return found ? METRICS_GREP_RET_KEEP : METRICS_GREP_RET_EXCLUDE;
    }

    /* The last rule is exclude */
    return found ? METRICS_GREP_RET_EXCLUDE : METRICS_GREP_RET_KEEP;
}

/* Given a msgpack metrics, do some filter action based on the defined rules */
static inline int grep_filter_metrics(struct cmt *cmt, struct cmt *out_cmt,
                                      struct metrics_grep_ctx *ctx)
{
    return grep_filter_metrics_and_op(cmt, out_cmt, ctx);
}

static inline int grep_filter_metrics_and_or(struct cmt *cmt, struct cmt *out_cmt,
                                             struct metrics_grep_ctx *ctx)
{
    ssize_t ret;

    if (ctx->logical_op == METRICS_GREP_LOGICAL_OP_OR) {
        ret = grep_filter_metrics_or_op(cmt, out_cmt, ctx);
    }
    else if (ctx->logical_op == METRICS_GREP_LOGICAL_OP_AND) {
        ret = grep_filter_metrics_and_op(cmt, out_cmt, ctx);
    }

    return ret;
}

static int process_metrics(struct flb_processor_instance *processor_instance,
                           struct cmt *metrics_context,
                           const char *tag,
                           int tag_len)
{
    int ret;
    struct metrics_grep_ctx *ctx;
    struct cmt *out_cmt = NULL;

    ctx = (struct metrics_grep_ctx *) processor_instance->context;

    out_cmt = cmt_create();
    if (out_cmt == NULL) {
        flb_plg_error(processor_instance, "could not create out_cmt context");
        return METRICS_GREP_FAILURE;
    }

    if (ctx->logical_op == METRICS_GREP_LOGICAL_OP_LEGACY) {
        ret = grep_filter_metrics(metrics_context, out_cmt, ctx);
    }
    else {
        ret = grep_filter_metrics_and_or(metrics_context, out_cmt, ctx);
    }

    if (ret == METRICS_GREP_FAILURE) {
        /* destroy cmt contexts */
        cmt_destroy(out_cmt);

        return METRICS_GREP_FAILURE;
    }

    if (ret == METRICS_GREP_RET_KEEP || ret == METRICS_GREP_RET_EXCLUDE) {
        /* destroy and recreate metrics context */
        cmt_destroy(metrics_context);
        metrics_context = NULL;

        metrics_context = cmt_create();
        if (metrics_context == NULL) {
            flb_plg_error(ctx->ins, "could not create metrics_context");
            /* destroy cmt contexts */
            cmt_destroy(out_cmt);

            return METRICS_GREP_FAILURE;
        }

        ret = cmt_cat(metrics_context, out_cmt);
    }

    if (ret == 0) {
        ret = METRICS_GREP_SUCCESS;
    }

    /* destroy cmt contexts */
    cmt_destroy(out_cmt);

    return ret;
}
#endif

static int cb_process_metrics_grep(struct flb_processor_instance *processor_instance,
                                    struct cmt *metrics_context,
                                    const char *tag,
                                    int tag_len)
{
    int result = METRICS_GREP_SUCCESS;

#ifdef FLB_HAVE_METRICS
    result = process_metrics(processor_instance,
                             metrics_context,
                             tag, tag_len);
#endif

    if (result != METRICS_GREP_SUCCESS) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_metrics_exit(struct flb_processor_instance *processor_instance)
{
    if (processor_instance != NULL &&
        processor_instance->context != NULL) {
        destroy_context(processor_instance->context);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "metrics.regex", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Keep metrics in which the metric of name matches the regular expression."
    },
    {
     FLB_CONFIG_MAP_STR, "metrics.exclude", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Exclude metrics in which the metric of name matches the regular expression."
    },
    {
     FLB_CONFIG_MAP_STR, "logical_op", "legacy",
     0, FLB_FALSE, 0,
     "Specify whether to use logical conjuciton or disjunction. legacy, AND and OR are allowed."
    },
    /* EOF */
    {0}
};

struct flb_processor_plugin processor_metrics_grep_plugin = {
    .name               = "metrics_grep",
    .description        = "grep metrics by specified name",
    .cb_init            = cb_process_metrics_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = cb_process_metrics_grep,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_process_metrics_exit,
    .config_map         = config_map,
    .flags              = 0
};
