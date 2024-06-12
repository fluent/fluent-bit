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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_regex.h>

#include "cm.h"

static int action_set_action(struct content_modifier_ctx *ctx,
                             struct content_modifier_action *action,
                             const char *action_str)
{
    if (strcasecmp(action_str, "insert") == 0) {
        action->type = CM_ACTION_INSERT;
    }
    else if (strcasecmp(action_str, "upsert") == 0) {
        action->type = CM_ACTION_UPSERT;
    }
    else if (strcasecmp(action_str, "delete") == 0) {
        action->type = CM_ACTION_DELETE;
    }
    else if (strcasecmp(action_str, "rename") == 0) {
        action->type = CM_ACTION_RENAME;
    }
    else if (strcasecmp(action_str, "hash") == 0) {
        action->type = CM_ACTION_HASH;
    }
    else if (strcasecmp(action_str, "extract") == 0) {
        action->type = CM_ACTION_EXTRACT;
    }
    else if (strcasecmp(action_str, "convert") == 0) {
        action->type = CM_ACTION_CONVERT;
    }
    else {
        flb_plg_error(ctx->ins, "unknown action '%s'", action_str);
        return -1;
    }

    return 0;
}

static int action_set_converted_type(struct content_modifier_ctx *ctx,
                                     struct content_modifier_action *act,
                                     const char *converted_type_str)
{
    int type = -1;

    if (!converted_type_str) {
        act->converted_type = -1;
    }

    if (strcasecmp(converted_type_str, "string") == 0) {
        type = CFL_VARIANT_STRING;
    }
    else if (strcasecmp(converted_type_str, "boolean") == 0) {
        type = CFL_VARIANT_BOOL;
    }
    else if (strcasecmp(converted_type_str, "int") == 0) {
        type = CFL_VARIANT_INT;
    }
    else if (strcasecmp(converted_type_str, "double") == 0) {
        type = CFL_VARIANT_DOUBLE;
    }
    else {
        flb_plg_error(ctx->ins, "unsupported converted_type '%s'", converted_type_str);
        return -1;
    }

    act->converted_type = type;
    return 0;
}

static int action_set_context(struct content_modifier_ctx *ctx,
                              struct content_modifier_action *act,
                              const char *context_str)
{
    int context = CM_CONTEXT_UNDEFINED;
    int event_type;

    /* The event type is set on the processor instance (coming from the proceesor_unit),
     * basically we need to know if this is being invoked for what type of telemetry
     * data.
     */
    event_type = ctx->ins->event_type;

    /*
     * Based on the action type, the action can be applied only to
     * specific context of the Telemetry type.
     */
    if (event_type == FLB_PROCESSOR_LOGS) {
        if (context_str == NULL) {
            /* if no context is set, use the log body */
            context = CM_CONTEXT_LOG_BODY;
        }
        else if (strcasecmp(context_str, "metadata") == 0 ||
            strcasecmp(context_str, "attributes") == 0) {
            context = CM_CONTEXT_LOG_METADATA;
        }
        else if (strcasecmp(context_str, "body") == 0 ||
                 strcasecmp(context_str, "message") == 0 ||
                 strcasecmp(context_str, "record") == 0) {
            context = CM_CONTEXT_LOG_BODY;
        }
        else {
            flb_plg_error(ctx->ins, "unknown logs context '%s'", context_str);
            return -1;
        }
    }
    else if (event_type == FLB_PROCESSOR_METRICS) {
        if (context_str == NULL) {
            /* if no context is set, use labels */
            context = CM_CONTEXT_METRIC_LABELS;
        }
        else if (strcasecmp(context_str, "name") == 0) {
            context = CM_CONTEXT_METRIC_NAME;
        }
        else if (strcasecmp(context_str, "description") == 0) {
            context = CM_CONTEXT_METRIC_DESCRIPTION;
        }
        else if (strcasecmp(context_str, "labels") == 0 ||
                 strcasecmp(context_str, "attributes") == 0) {
            context = CM_CONTEXT_METRIC_LABELS;
        }
        else {
            flb_plg_error(ctx->ins, "unknown metrics context '%s'", context_str);
            return -1;
        }
    }
    else if (event_type == FLB_PROCESSOR_TRACES) {
        if (context_str == NULL) {
            /* if no context is set, use span attributes */
            context = CM_CONTEXT_TRACE_SPAN_ATTRIBUTES;
        }
        else if (strcasecmp(context_str, "span_name") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_NAME;
        }
        else if (strcasecmp(context_str, "span_kind") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_KIND;
        }
        else if (strcasecmp(context_str, "span_status") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_STATUS;
        }
        else if (strcasecmp(context_str, "span_attributes") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_ATTRIBUTES;
        }
        else {
            flb_plg_error(ctx->ins, "unknown traces context '%s'", context_str);
            return -1;
        }
    }

    act->context_type = context;
    return 0;
}

static int check_action_requirements(struct content_modifier_ctx *ctx,
                                     struct content_modifier_action *act)
{
    int ret;

    if (!act->key) {
        flb_plg_error(ctx->ins, "key is required for action");
        return -1;
    }

    if (act->type == CM_ACTION_DELETE || act->type == CM_ACTION_HASH) {
        /* these only requires a key, already validated (useless code) */
    }
    else if (act->type == CM_ACTION_INSERT || act->type == CM_ACTION_UPSERT ||
        act->type == CM_ACTION_RENAME) {

        if (!act->value) {
            flb_plg_error(ctx->ins, "value is required for action");
            return -1;
        }
    }
    else if (act->type == CM_ACTION_EXTRACT) {
        if (!act->pattern) {
            flb_plg_error(ctx->ins, "for 'extract' action, a regular expression in 'pattern' is required");
            return -1;
        }
    }
    else if (act->type == CM_ACTION_CONVERT) {
        if (act->converted_type == -1) {
            flb_plg_error(ctx->ins, "converted_type is required for action");
            return -1;
        }
    }

    return 0;
}
struct content_modifier_ctx *cm_config_create(struct flb_processor_instance *ins,
                                              struct flb_config *config)

{
    int ret;
    int idx;
    struct content_modifier_ctx *ctx;
    struct mk_list *head;
    struct flb_config_map_val *entry;
    struct cfl_kvlist *action;
    struct cfl_variant *op;
    struct cfl_variant *key;
    struct cfl_variant *value;
    struct cfl_variant *pattern;
    struct cfl_variant *context;
    struct cfl_variant *converted_type;
    struct content_modifier_action *act;

    /* Create plugin instance context */
    ctx = flb_calloc(1, sizeof(struct content_modifier_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Initialize the config map */
    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    if (!ctx->action_str && (ctx->actions_list == NULL || ctx->actions_list->entry_count == 0)) {
        flb_plg_error(ctx->ins, "no 'action' defined");
        flb_free(ctx);
        return NULL;
    }

    mk_list_init(&ctx->actions);

    if (ctx->action_str) {
        act = flb_calloc(1, sizeof(struct content_modifier_action));
        if (act == NULL) {
            flb_plg_error(ctx->ins, "unable to allocate memory for action");
            flb_free(ctx);
            return NULL;
        }

        act->converted_type = -1;

        /* process the 'action' configuration */
        ret = action_set_action(ctx, act, ctx->action_str);
        if (ret == -1) {
            flb_free(act);
            flb_free(ctx);
            return NULL;
        }

        /* process the 'context' where the action will be applied */
        ret = action_set_context(ctx, act, ctx->context_str);
        if (ret == -1) {
            flb_free(act);
            flb_free(ctx);
            return NULL;
        }

        /* Pattern */
        if (ctx->pattern) {
            act->pattern = flb_regex_create(ctx->pattern);
            if (!act->pattern) {
                flb_plg_error(ctx->ins, "invalid regex pattern '%s'", ctx->pattern);
                flb_free(ctx);
                return NULL;
            }
        }

        if (ctx->key) {
            act->key = flb_sds_create(ctx->key);
        }

        if (ctx->value) {
            act->key = flb_sds_create(ctx->value);
        }

        if (ctx->converted_type_str) {
            action_set_converted_type(ctx, act, ctx->converted_type_str);
        }

        /* Certain actions needs extra configuration, e.g: insert -> requires a key and a value */
        ret = check_action_requirements(ctx, act);
        if (ret == -1) {
                flb_free(ctx);
                flb_free(act);
                return NULL;
        }

        mk_list_add(&act->_head, &ctx->actions);
    }
    else {
        for (idx = 0; idx < ctx->actions_list->entry_count; idx++) {
            action = ctx->actions_list->entries[idx]->data.as_kvlist;

            act = flb_calloc(1, sizeof(struct content_modifier_action));
            if (act == NULL) {
                flb_free(ctx);
                return NULL;
            }

            op = cfl_kvlist_fetch(action, "action");
            if (op == NULL) {
                flb_free(ctx);
                flb_free(act);
                return NULL;
            }
            action_set_action(ctx, act, op->data.as_string);

            context = cfl_kvlist_fetch(action, "context");

            if (context) {
                action_set_context(ctx, act, context->data.as_string);
            }
            else {
                action_set_context(ctx, act, NULL);
            }

            key = cfl_kvlist_fetch(action, "key");
            if (key) {
                act->key = flb_sds_create(key->data.as_string);
            }

            value = cfl_kvlist_fetch(action, "value");
            if (value) {
                act->value = flb_sds_create(value->data.as_string);
            }

            pattern = cfl_kvlist_fetch(action, "pattern");
            if (pattern) {
                act->pattern = flb_regex_create(pattern->data.as_string);
                if (!act->pattern) {
                    flb_plg_error(ctx->ins, "invalid regex pattern '%s'", pattern);
                    flb_free(ctx);
                    return NULL;
                }
            }

            converted_type = cfl_kvlist_fetch(action, "converted_type");
            if (converted_type) {
                 action_set_converted_type(ctx, act, converted_type->data.as_string);
            }

            /* Certain actions needs extra configuration, e.g: insert -> requires a key and a value */
            ret = check_action_requirements(ctx, act);
            if (ret == -1) {
                    flb_free(ctx);
                    flb_free(act);
                    return NULL;
            }

            mk_list_add(&act->_head, &ctx->actions);
        }
    }

    return ctx;
}

void cm_config_destroy(struct content_modifier_ctx *ctx)
{
    // if (ctx->pattern) {
    //     flb_regex_destroy(ctx->pattern);
    // }

    flb_free(ctx);
}
