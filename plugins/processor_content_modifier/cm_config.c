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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_regex.h>

#include "cm.h"

static int set_action(struct content_modifier_ctx *ctx)
{
    if (strcasecmp(ctx->action_str, "insert") == 0) {
        ctx->action_type = CM_ACTION_INSERT;
    }
    else if (strcasecmp(ctx->action_str, "upsert") == 0) {
        ctx->action_type = CM_ACTION_UPSERT;
    }
    else if (strcasecmp(ctx->action_str, "delete") == 0) {
        ctx->action_type = CM_ACTION_DELETE;
    }
    else if (strcasecmp(ctx->action_str, "rename") == 0) {
        ctx->action_type = CM_ACTION_RENAME;
    }
    else if (strcasecmp(ctx->action_str, "hash") == 0) {
        ctx->action_type = CM_ACTION_HASH;
    }
    else if (strcasecmp(ctx->action_str, "extract") == 0) {
        ctx->action_type = CM_ACTION_EXTRACT;
    }
    else if (strcasecmp(ctx->action_str, "convert") == 0) {
        ctx->action_type = CM_ACTION_CONVERT;
    }
    else {
        flb_plg_error(ctx->ins, "unknown action '%s'", ctx->action_str);
        return -1;
    }

    return 0;
}

static int set_converted_type(struct content_modifier_ctx *ctx)
{
    int type = -1;

    if (!ctx->converted_type_str) {
        ctx->converted_type = -1;
    }

    if (strcasecmp(ctx->converted_type_str, "string") == 0) {
        type = CFL_VARIANT_STRING;
    }
    else if (strcasecmp(ctx->converted_type_str, "boolean") == 0) {
        type = CFL_VARIANT_BOOL;
    }
    else if (strcasecmp(ctx->converted_type_str, "int") == 0) {
        type = CFL_VARIANT_INT;
    }
    else if (strcasecmp(ctx->converted_type_str, "double") == 0) {
        type = CFL_VARIANT_DOUBLE;
    }
    else {
        flb_plg_error(ctx->ins, "unsupported converted_type '%s'", ctx->converted_type_str);
        return -1;
    }

    ctx->converted_type = type;
    return 0;
}

static int set_context(struct content_modifier_ctx *ctx)
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
        if (ctx->context_str == NULL) {
            /* if no context is set, use the log body */
            context = CM_CONTEXT_LOG_BODY;
        }
        else if (strcasecmp(ctx->context_str, "metadata") == 0 ||
            strcasecmp(ctx->context_str, "attributes") == 0) {
            context = CM_CONTEXT_LOG_METADATA;
        }
        else if (strcasecmp(ctx->context_str, "body") == 0 ||
                 strcasecmp(ctx->context_str, "message") == 0 ||
                 strcasecmp(ctx->context_str, "record") == 0) {
            context = CM_CONTEXT_LOG_BODY;
        }
        /*
         * OpenTelemetry contexts
         * ----------------------
         */
        else if (strcasecmp(ctx->context_str, "otel_resource_attributes") == 0) {
            context = CM_CONTEXT_OTEL_RESOURCE_ATTR;
        }
        else if (strcasecmp(ctx->context_str, "otel_scope_name") == 0) {
            /*
             * scope name is restricted to specific actions, make sure the user
             * cannot messed it up
             *
             *   action              allowed ?
             *   -----------------------------
             *   CM_ACTION_INSERT       Yes
             *   CM_ACTION_UPSERT       Yes
             *   CM_ACTION_DELETE       Yes
             *   CM_ACTION_RENAME        No
             *   CM_ACTION_HASH         Yes
             *   CM_ACTION_EXTRACT       No
             *   CM_ACTION_CONVERT       No
             */

            if (ctx->action_type == CM_ACTION_RENAME ||
                ctx->action_type == CM_ACTION_EXTRACT ||
                ctx->action_type == CM_ACTION_CONVERT) {
                flb_plg_error(ctx->ins, "action '%s' is not allowed for context '%s'",
                              ctx->action_str, ctx->context_str);
                return -1;
            }

            /* check that 'name' is the key set */
            if (!ctx->key) {
                ctx->key = flb_sds_create("name");
            }
            else if (strcasecmp(ctx->key, "name") != 0) {
                flb_plg_error(ctx->ins, "context '%s' requires the name of the key to be 'name', no '%s'",
                              ctx->context_str, ctx->key);
                return -1;
            }

            context = CM_CONTEXT_OTEL_SCOPE_NAME;
        }
        else if (strcasecmp(ctx->context_str, "otel_scope_version") == 0) {
            /*
             * scope version, same as the name, it's restricted to specific actions, make sure the user
             * cannot messed it up
             *
             *   action              allowed ?
             *   -----------------------------
             *   CM_ACTION_INSERT       Yes
             *   CM_ACTION_UPSERT       Yes
             *   CM_ACTION_DELETE       Yes
             *   CM_ACTION_RENAME        No
             *   CM_ACTION_HASH         Yes
             *   CM_ACTION_EXTRACT       No
             *   CM_ACTION_CONVERT       No
             */

            if (ctx->action_type == CM_ACTION_RENAME ||
                ctx->action_type == CM_ACTION_EXTRACT ||
                ctx->action_type == CM_ACTION_CONVERT) {
                flb_plg_error(ctx->ins, "action '%s' is not allowed for context '%s'",
                              ctx->action_str, ctx->context_str);
                return -1;
            }

            /* check that 'version' is the key set */
            if (!ctx->key) {
                ctx->key = flb_sds_create("version");
            }
            else if (strcasecmp(ctx->key, "version") != 0) {
                flb_plg_error(ctx->ins, "context '%s' requires the name of the key to be 'version', no '%s'",
                              ctx->context_str, ctx->key);
                return -1;
            }
            context = CM_CONTEXT_OTEL_SCOPE_VERSION;
        }
        else if (strcasecmp(ctx->context_str, "otel_scope_attributes") == 0) {
            context = CM_CONTEXT_OTEL_SCOPE_ATTR;
        }
        else if (strcasecmp(ctx->context_str, "otel_scope_name") == 0) {
        }
        else if (strcasecmp(ctx->context_str, "otel_scope_version") == 0) {
            context = CM_CONTEXT_OTEL_SCOPE_VERSION;
        }
        else {
            flb_plg_error(ctx->ins, "unknown logs context '%s'", ctx->context_str);
            return -1;
        }
    }
    else if (event_type == FLB_PROCESSOR_METRICS) {
        if (ctx->context_str == NULL) {
            /* if no context is set, use labels */
            context = CM_CONTEXT_METRIC_LABELS;
        }
        else if (strcasecmp(ctx->context_str, "name") == 0) {
            context = CM_CONTEXT_METRIC_NAME;
        }
        else if (strcasecmp(ctx->context_str, "description") == 0) {
            context = CM_CONTEXT_METRIC_DESCRIPTION;
        }
        else if (strcasecmp(ctx->context_str, "labels") == 0 ||
                 strcasecmp(ctx->context_str, "attributes") == 0) {
            context = CM_CONTEXT_METRIC_LABELS;
        }

        /*
         * OpenTelemetry contexts
         * ----------------------
         */
        else if (strcasecmp(ctx->context_str, "otel_resource_attributes") == 0) {
            context = CM_CONTEXT_OTEL_RESOURCE_ATTR;
        }
        else if (strcasecmp(ctx->context_str, "otel_scope_attributes") == 0) {
            context = CM_CONTEXT_OTEL_SCOPE_ATTR;
        }
        else if (strcasecmp(ctx->context_str, "otel_scope_name") == 0) {
            /*
             * scope name is restricted to specific actions, make sure the user
             * cannot messed it up
             *
             *   action              allowed ?
             *   -----------------------------
             *   CM_ACTION_INSERT       Yes
             *   CM_ACTION_UPSERT       Yes
             *   CM_ACTION_DELETE       Yes
             *   CM_ACTION_RENAME        No
             *   CM_ACTION_HASH         Yes
             *   CM_ACTION_EXTRACT       No
             *   CM_ACTION_CONVERT       No
             */

            if (ctx->action_type == CM_ACTION_RENAME ||
                ctx->action_type == CM_ACTION_EXTRACT ||
                ctx->action_type == CM_ACTION_CONVERT) {
                flb_plg_error(ctx->ins, "action '%s' is not allowed for context '%s'",
                              ctx->action_str, ctx->context_str);
                return -1;
            }

            /* check that 'name' is the key set */
            if (!ctx->key) {
                ctx->key = flb_sds_create("name");
            }
            else if (strcasecmp(ctx->key, "name") != 0) {
                flb_plg_error(ctx->ins, "context '%s' requires the name of the key to be 'name', no '%s'",
                              ctx->context_str, ctx->key);
                return -1;
            }

            context = CM_CONTEXT_OTEL_SCOPE_NAME;
        }
        else {
            flb_plg_error(ctx->ins, "unknown metrics context '%s'", ctx->context_str);
            return -1;
        }
    }
    else if (event_type == FLB_PROCESSOR_TRACES) {
        if (ctx->context_str == NULL) {
            /* if no context is set, use span attributes */
            context = CM_CONTEXT_TRACE_SPAN_ATTRIBUTES;
        }
        else if (strcasecmp(ctx->context_str, "span_name") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_NAME;
        }
        else if (strcasecmp(ctx->context_str, "span_kind") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_KIND;
        }
        else if (strcasecmp(ctx->context_str, "span_status") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_STATUS;
        }
        else if (strcasecmp(ctx->context_str, "span_attributes") == 0) {
            context = CM_CONTEXT_TRACE_SPAN_ATTRIBUTES;
        }
        else {
            flb_plg_error(ctx->ins, "unknown traces context '%s'", ctx->context_str);
            return -1;
        }
    }

    ctx->context_type = context;
    return 0;
}

static int check_action_requirements(struct content_modifier_ctx *ctx)
{
    int ret;

    if (!ctx->key) {
        flb_plg_error(ctx->ins, "key is required for action '%s'", ctx->action_str);
        return -1;
    }

    if (ctx->action_type == CM_ACTION_DELETE || ctx->action_type == CM_ACTION_HASH) {
        /* these only requires a key, already validated (useless code) */
    }
    else if (ctx->action_type == CM_ACTION_INSERT || ctx->action_type == CM_ACTION_UPSERT ||
             ctx->action_type == CM_ACTION_RENAME) {

        if (!ctx->value) {
            flb_plg_error(ctx->ins, "value is required for action '%s'", ctx->action_str);
            return -1;
        }
    }
    else if (ctx->action_type == CM_ACTION_EXTRACT) {
        if (!ctx->pattern) {
            flb_plg_error(ctx->ins, "for 'extract' action, a regular expression in 'pattern' is required");
            return -1;
        }
    }
    else if (ctx->action_type == CM_ACTION_CONVERT) {
        if (!ctx->converted_type_str) {
            flb_plg_error(ctx->ins, "converted_type is required for action '%s'", ctx->action_str);
            return -1;
        }

        ret = set_converted_type(ctx);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot set converted_type '%s'", ctx->converted_type_str);
            return -1;
        }
    }

    return 0;
}
struct content_modifier_ctx *cm_config_create(struct flb_processor_instance *ins,
                                              struct flb_config *config)

{
    int ret;
    struct content_modifier_ctx *ctx;

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

    if (!ctx->action_str) {
        flb_plg_error(ctx->ins, "no 'action' defined");
        flb_free(ctx);
        return NULL;
    }

    /* process the 'action' configuration */
    ret = set_action(ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* process the 'context' where the action will be applied */
    ret = set_context(ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Pattern */
    if (ctx->pattern) {
        ctx->regex = flb_regex_create(ctx->pattern);
        if (!ctx->regex) {
            flb_plg_error(ctx->ins, "invalid regex pattern '%s'", ctx->pattern);
            flb_free(ctx);
            return NULL;
        }
    }

    /* Certain actions needs extra configuration, e.g: insert -> requires a key and a value */
    ret = check_action_requirements(ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }
    return ctx;
}

void cm_config_destroy(struct content_modifier_ctx *ctx)
{
    if (ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }

    flb_free(ctx);
}
