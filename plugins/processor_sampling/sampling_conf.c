/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_kv.h>

#include "sampling.h"

static int sampling_type_lookup(const char *type_str)
{
    if (strcasecmp(type_str, "test") == 0) {
        return SAMPLING_TYPE_TEST;
    }
    else if (strcasecmp(type_str, "probabilistic") == 0) {
        return SAMPLING_TYPE_PROBABILISTIC;
    }
    else if (strcasecmp(type_str, "tail") == 0) {
        return SAMPLING_TYPE_TAIL;
    }

    return -1;
}

static char *sampling_config_type_str(int type)
{
    switch (type) {
    case SAMPLING_TYPE_TEST:
        return "test";
    case SAMPLING_TYPE_PROBABILISTIC:
        return "probabilistic";
    case SAMPLING_TYPE_TAIL:
        return "tail";
    default:
        return "unknown";
    }
}

static struct sampling_plugin *sampling_config_get_plugin(int type)
{
    struct sampling_plugin *plugin = NULL;

    switch (type) {
    /*
        case SAMPLING_TYPE_TEST:
        plugin = &sampling_test_plugin;
        break;
    */
    case SAMPLING_TYPE_PROBABILISTIC:
        plugin = &sampling_probabilistic_plugin;
        break;
    case SAMPLING_TYPE_TAIL:
        plugin = &sampling_tail_plugin;
        break;
    default:
        plugin = NULL;
    }

    return plugin;
}

/* Register properties inside 'rules' into the ctx->plugin_rules_properties list */
 int sampling_config_process_rules(struct flb_config *config, struct sampling *ctx)
{
    int ret;
    char val[1024];
    struct cfl_list *head;
    struct cfl_variant *var;
    struct cfl_kvlist *kv;
    struct cfl_kvpair *pair;
    struct mk_list *map;
    struct flb_kv *kv_entry;

    if (!ctx->sampling_settings) {
        /* no rules have been defined */
        return 0;
    }

    var = ctx->sampling_settings;
    if (var->type != CFL_VARIANT_KVLIST) {
        flb_plg_error(ctx->ins, "rules must be a map");
        return -1;
    }

    kv = var->data.as_kvlist;
    cfl_list_foreach(head, &kv->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (pair->val->type != CFL_VARIANT_INT &&
            pair->val->type != CFL_VARIANT_UINT &&
            pair->val->type != CFL_VARIANT_STRING &&
            pair->val->type != CFL_VARIANT_BOOL &&
            pair->val->type != CFL_VARIANT_DOUBLE) {
            flb_plg_error(ctx->ins, "invalid value type for key '%s'", pair->key);
            return -1;
        }

        /*
         * Internal kvlist expects the value to be in string format, convert them from native
         * to it string version. We might need a better interface for this.
         */
        ret = -1;

        if (pair->val->type == CFL_VARIANT_INT) {
            ret = snprintf(val, sizeof(val) - 1, "%ld", pair->val->data.as_int64);
        }
        else if (pair->val->type == CFL_VARIANT_UINT) {
            ret = snprintf(val, sizeof(val) - 1, "%ld", pair->val->data.as_uint64);
        }
        else if (pair->val->type == CFL_VARIANT_DOUBLE) {
            ret = snprintf(val, sizeof(val) - 1, "%f", pair->val->data.as_double);
        }
        else if (pair->val->type == CFL_VARIANT_BOOL) {
            ret = snprintf(val, sizeof(val) - 1, "%s", pair->val->data.as_bool ? "true" : "false");
        }
        else if (pair->val->type == CFL_VARIANT_STRING) {
            ret = snprintf(val, sizeof(val) - 1, "%s", pair->val->data.as_string);
        }
        else {
            flb_plg_error(ctx->ins, "invalid value type for key '%s'", pair->key);
            return -1;
        }

        if (ret <= 0) {
            flb_plg_error(ctx->ins, "failed to convert value to string");
            return -1;
        }

        kv_entry = flb_kv_item_create_len(&ctx->plugin_settings_properties, pair->key, strlen(pair->key), val, ret);
        if (!kv_entry) {
            flb_plg_error(ctx->ins, "failed to create kv entry for rule key '%s'", pair->key);
            return -1;
        }
    }

    map = flb_config_map_create(config, ctx->plugin->config_map);
    if (!map) {
        flb_plg_error(ctx->ins, "failed to create map for plugin rules");
        return -1;
    }
    ctx->plugin_config_map = map;

    ret = flb_config_map_properties_check(ctx->type_str, &ctx->plugin_settings_properties, map);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to validate plugin rules properties");
        return -1;
    }

    return 0;
}

struct sampling *sampling_config_create(struct flb_processor_instance *processor_instance,
                                        struct flb_config *config)
{
    int ret;
    struct sampling *ctx;
    struct sampling_plugin *plugin_context;
    struct sampling_conditions *sampling_conditions;

    ctx = flb_calloc(1, sizeof(struct sampling));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = processor_instance;
    ctx->input_ins = flb_processor_get_input_instance(ctx->ins->pu);

    /* config map */
    ret = flb_processor_instance_config_map_set(processor_instance, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* sampling type: this is mandatory */
    if (!ctx->type_str) {
        flb_plg_error(processor_instance, "no sampling 'type' defined");
        flb_free(ctx);
        return NULL;
    }

    /* type (int) */
    ret = sampling_type_lookup(ctx->type_str);
    if (ret == -1) {
        flb_plg_error(processor_instance, "unknown sampling type '%s'", ctx->type_str);
        flb_free(ctx);
        return NULL;
    }
    ctx->type = ret;

    plugin_context = sampling_config_get_plugin(ctx->type);
    if (!plugin_context) {
        flb_plg_error(processor_instance, "no plugin context found for sampling type '%s'",
                      sampling_config_type_str(ctx->type));
        flb_free(ctx);
        return NULL;
    }
    ctx->plugin = plugin_context;

    cfl_list_init(&ctx->plugins);
    flb_kv_init(&ctx->plugin_settings_properties);

    /* load conditions */
    if (ctx->conditions) {
        sampling_conditions = sampling_conditions_create(ctx, ctx->conditions);
        if (!sampling_conditions) {
            flb_plg_error(processor_instance, "failed to create conditions");
            flb_free(ctx);
            return NULL;
        }
        ctx->sampling_conditions = sampling_conditions;
    }

    return ctx;
}

void sampling_config_destroy(struct flb_config *config, struct sampling *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->sampling_conditions) {
        sampling_conditions_destroy(ctx->sampling_conditions);
    }

    if (ctx->plugin) {
        if (ctx->plugin->cb_exit) {
            ctx->plugin->cb_exit(config, ctx->plugin_context);
        }
    }

    flb_kv_release(&ctx->plugin_settings_properties);

    if (ctx->plugin_config_map) {
        flb_config_map_destroy(ctx->plugin_config_map);
    }

    flb_free(ctx);
}
