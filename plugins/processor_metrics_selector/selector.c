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
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_metrics.h>
#include <msgpack.h>

#include "selector.h"

static void delete_metrics_rules(struct selector_ctx *ctx)
{
    if (ctx->name_regex != NULL) {
        flb_regex_destroy(ctx->name_regex);
    }
}

static void destroy_context(struct selector_ctx *context)
{
    if (context != NULL) {
        delete_metrics_rules(context);
        if (context->selector_pattern != NULL) {
            flb_free(context->selector_pattern);
        }
        if (context->label_key != NULL) {
            flb_sds_destroy(context->label_key);
        }
        if (context->label_value != NULL) {
            flb_sds_destroy(context->label_value);
        }
        flb_free(context);
    }
}

static int set_metrics_rules(struct selector_ctx *ctx, struct flb_processor_instance *p_ins)
{
    flb_sds_t tmp;
    const char *action;
    const char *metric_name;
    const char *op_type;
    const char *context;
    const char *label;
    size_t name_len = 0;
    struct mk_list *split;
    struct flb_split_entry *sentry;

    ctx->selector_pattern = NULL;
    ctx->label_key = NULL;
    ctx->label_value = NULL;

    context = flb_processor_instance_get_property("context", p_ins);
    if (context == NULL) {
        ctx->context_type = SELECTOR_CONTEXT_FQNAME;
    }
    else if (strncasecmp(context, "metric_name", 11) == 0) {
        ctx->context_type = SELECTOR_CONTEXT_FQNAME;
    }
    else if (strncasecmp(context, "delete_label_value", 18) == 0) {
        ctx->context_type = SELECTOR_CONTEXT_DELETE_LABEL_VALUE;
    }
    else {
        flb_plg_error(ctx->ins, "unknown context '%s'", context);
        delete_metrics_rules(ctx);
        return -1;
    }

    if (ctx->context_type == SELECTOR_CONTEXT_FQNAME) {
        action = flb_processor_instance_get_property("action", p_ins);
        if (action == NULL) {
            ctx->action_type = SELECTOR_INCLUDE;
        }
        else if (strncasecmp(action, "include", 7) == 0) {
            flb_plg_debug(ctx->ins, "action type INCLUDE");
            ctx->action_type = SELECTOR_INCLUDE;
        }
        else if (strncasecmp(action, "exclude", 7) == 0) {
            flb_plg_debug(ctx->ins, "action type EXCLUDE");
            ctx->action_type = SELECTOR_EXCLUDE;
        }
        else {
            flb_plg_error(ctx->ins, "unknown action type '%s'", action);
            return -1;
        }

        metric_name = flb_processor_instance_get_property("metric_name", p_ins);
        if (metric_name == NULL) {
            flb_plg_error(ctx->ins, "metric_name is needed for selector");
            return -1;
        }
        ctx->selector_pattern = flb_strdup(metric_name);
        name_len = strlen(metric_name);

        op_type = flb_processor_instance_get_property("operation_type", p_ins);
        if (op_type == NULL) {
            ctx->op_type = SELECTOR_OPERATION_PREFIX;
        }
        else if (strncasecmp(op_type, "prefix", 6) == 0) {
            flb_plg_debug(ctx->ins, "operation type PREFIX");
            ctx->op_type = SELECTOR_OPERATION_PREFIX;
        }
        else if (strncasecmp(op_type, "substring", 9) == 0) {
            flb_plg_debug(ctx->ins, "operation type SUBSTRING");
            ctx->op_type = SELECTOR_OPERATION_SUBSTRING;
        }
        else {
            flb_plg_error(ctx->ins, "unknown action type '%s'", op_type);
            return -1;
        }

        if (ctx->selector_pattern[0] == '/' && ctx->selector_pattern[name_len-1] == '/') {
            /* Convert string to regex pattern for metrics */
            ctx->name_regex = flb_regex_create(ctx->selector_pattern);
            if (!ctx->name_regex) {
                flb_plg_error(ctx->ins, "could not compile regex pattern '%s'",
                              ctx->selector_pattern);
                return -1;
            }
            ctx->op_type = SELECTOR_OPERATION_REGEX;
        }
    }
    else if (ctx->context_type == SELECTOR_CONTEXT_DELETE_LABEL_VALUE) {
        label = flb_processor_instance_get_property("label", p_ins);
        if (label != NULL) {
            split = flb_utils_split(label, ' ', 1);
            if (mk_list_size(split) != 2) {
                flb_plg_error(ctx->ins, "invalid value, expected key and value");
                flb_utils_split_free(split);
                return -1;
            }

            /* Get first value (label's key) */
            sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
            tmp = flb_sds_create_len(sentry->value, sentry->len);
            if (tmp == NULL) {
                flb_plg_error(ctx->ins, "allocation failed for label key");
                flb_utils_split_free(split);
                return -1;
            }
            ctx->label_key = tmp;

            /* Get last value (label's value) */
            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            tmp = flb_sds_create_len(sentry->value, sentry->len);
            if (tmp == NULL) {
                flb_plg_error(ctx->ins, "allocation failed for label value");
                flb_utils_split_free(split);
                return -1;
            }
            ctx->label_value = tmp;
            ctx->op_type = SELECTOR_CONTEXT_DELETE_LABEL_VALUE;

            flb_utils_split_free(split);
        }
    }

    return 0;
}

static struct selector_ctx *
        create_context(struct flb_processor_instance *processor_instance,
                       struct flb_config *config)
{
    int result;
    struct selector_ctx *ctx;

    ctx = flb_malloc(sizeof(struct selector_ctx));
    if (ctx != NULL) {
        ctx->ins = processor_instance;
        ctx->config = config;
        ctx->name_regex = NULL;

        result = flb_processor_instance_config_map_set(processor_instance, (void *) ctx);

        if (result == 0) {
            /* Load rules */
            result= set_metrics_rules(ctx, processor_instance);
            if (result == -1) {
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


static int cb_selector_init(struct flb_processor_instance *processor_instance,
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
    unsigned char *s = (unsigned char *)str;
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
    unsigned char *s = (unsigned char *)str;
    ret = flb_regex_match(r, s, slen);

    if (ret == 1) {
        ret = CMT_FALSE;
    }
    else {
        ret = CMT_TRUE;
    }

    return ret;
}

static inline int selector_metrics_process_fqname(struct cmt *cmt, struct cmt *out_cmt,
                                                  struct selector_ctx *ctx)
{
    int ret = -1;
    int found = FLB_FALSE;
    struct cmt *filtered = NULL;
    int flags = 0;

    /* On processor_selector, we only process one rule in each of contexts */

    filtered = cmt_create();
    if (filtered == NULL) {
        flb_plg_error(ctx->ins, "could not create filtered context");

        return SELECTOR_FAILURE;
    }

    if (ctx->op_type == SELECTOR_OPERATION_REGEX) {
        if (ctx->action_type == SELECTOR_INCLUDE) {
            ret = cmt_filter(filtered, cmt, NULL, NULL, ctx->name_regex, cmt_regex_match, 0);
        }
        else if (ctx->action_type == SELECTOR_EXCLUDE) {
            ret = cmt_filter(filtered, cmt, NULL, NULL, ctx->name_regex, cmt_regex_exclude, 0);
        }
    }
    else if (ctx->selector_pattern != NULL) {
        if (ctx->action_type == SELECTOR_EXCLUDE) {
            flags |= CMT_FILTER_EXCLUDE;
        }

        if (ctx->op_type == SELECTOR_OPERATION_PREFIX) {
            flags |= CMT_FILTER_PREFIX;
        }
        else if (ctx->op_type == SELECTOR_OPERATION_SUBSTRING) {
            flags |= CMT_FILTER_SUBSTRING;
        }

        ret = cmt_filter(filtered, cmt, ctx->selector_pattern, NULL, NULL, NULL, flags);
    }

    if (ret == 0) {
        found = FLB_TRUE;
    }
    else if (ret != 0) {
        flb_plg_debug(ctx->ins, "not matched for rule = \"%s\"", ctx->selector_pattern);
    }

    cmt_cat(out_cmt, filtered);
    cmt_destroy(filtered);

    if (ctx->action_type == SELECTOR_INCLUDE) {
        return found ? SELECTOR_RET_KEEP : SELECTOR_RET_EXCLUDE;
    }

    /* The last rule is exclude */
    return found ? SELECTOR_RET_EXCLUDE : SELECTOR_RET_KEEP;
}

static inline int selector_metrics_process_delete_label_value(struct cmt *cmt, struct cmt *out_cmt,
                                                              struct selector_ctx *ctx)
{
    int ret;
    int removed = FLB_FALSE;
    struct cmt *filtered = NULL;

    /* On processor_selector, we only process one rule in each of contexts */

    filtered = cmt_create();
    if (filtered == NULL) {
        flb_plg_error(ctx->ins, "could not create filtered context");

        return SELECTOR_FAILURE;
    }

    ret = cmt_filter_with_label_pair(filtered, cmt, ctx->label_key, ctx->label_value);

    if (ret == 0) {
        removed = FLB_TRUE;
    }
    else if (ret != 0) {
        flb_plg_debug(ctx->ins, "not matched for a key-value pair: \"%s\",\"%s\"",
                      ctx->label_key, ctx->label_value);
    }

    cmt_cat(out_cmt, filtered);
    cmt_destroy(filtered);

    return removed ? SELECTOR_RET_EXCLUDE : SELECTOR_RET_KEEP;
}

/* Given a metrics context, do some select action based on the defined rules */
static inline int selector_metrics(struct cmt *cmt, struct cmt *out_cmt,
                                   struct selector_ctx *ctx)
{
    if (ctx->context_type == SELECTOR_CONTEXT_FQNAME) {
        return selector_metrics_process_fqname(cmt, out_cmt, ctx);
    }
    else if (ctx->context_type == SELECTOR_CONTEXT_DELETE_LABEL_VALUE) {
        return selector_metrics_process_delete_label_value(cmt, out_cmt, ctx);
    }

    return 0;
}

static int process_metrics(struct flb_processor_instance *processor_instance,
                           struct cmt *metrics_context,
                           struct cmt **out_context,
                           const char *tag,
                           int tag_len)
{
    int ret;
    struct selector_ctx *ctx;
    struct cmt *out_cmt;

    ctx = (struct selector_ctx *) processor_instance->context;

    out_cmt = cmt_create();
    if (out_cmt == NULL) {
        flb_plg_error(processor_instance, "could not create out_cmt context");
        return SELECTOR_FAILURE;
    }

    ret = selector_metrics(metrics_context, out_cmt, ctx);

    if (ret == SELECTOR_RET_KEEP || ret == SELECTOR_RET_EXCLUDE) {
        ret = SELECTOR_SUCCESS;
        *out_context = out_cmt;
    }
    else {
        /* destroy out_context contexts */
        cmt_destroy(out_cmt);

        ret = SELECTOR_FAILURE;
    }

    return ret;
}
#endif

static int cb_selector_process_metrics(struct flb_processor_instance *processor_instance,
                                       struct cmt *metrics_context,
                                       struct cmt **out_context,
                                       const char *tag,
                                       int tag_len)
{
    int result = SELECTOR_SUCCESS;

#ifdef FLB_HAVE_METRICS
    result = process_metrics(processor_instance,
                             metrics_context,
                             out_context,
                             tag, tag_len);
#endif

    if (result != SELECTOR_SUCCESS) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_selector_exit(struct flb_processor_instance *processor_instance, void *data)
{
    if (processor_instance != NULL && data != NULL) {
        destroy_context(data);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "metric_name", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Keep metrics in which the metric of name matches with the actual name or the regular expression."
    },
    {
     FLB_CONFIG_MAP_STR, "context", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Specify matching context. Currently, metric_name and delete_label_value are only supported."
    },
    {
     FLB_CONFIG_MAP_STR, "action", NULL,
     0, FLB_FALSE, 0,
     "Specify the action for specified metrics. INCLUDE and EXCLUDE are allowed."
    },
    {
     FLB_CONFIG_MAP_STR, "label", NULL,
     0, FLB_FALSE, 0,
     "Specify a label key and value pair."
    },
    {
     FLB_CONFIG_MAP_STR, "operation_type", NULL,
     0, FLB_FALSE, 0,
     "Specify the operation type of action for metrics payloads. PREFIX and SUBSTRING are allowed."
    },    /* EOF */
    {0}
};

struct flb_processor_plugin processor_metrics_selector_plugin = {
    .name               = "metrics_selector",
    .description        = "select metrics by specified name",
    .cb_init            = cb_selector_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = cb_selector_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_selector_exit,
    .config_map         = config_map,
    .flags              = 0
};
