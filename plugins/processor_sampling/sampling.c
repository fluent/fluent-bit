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
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_hash_table.h>

#include "sampling.h"
#include "sampling_span_registry.h"

static int clean_empty_resource_spans(struct ctrace *ctr)
{
    int count = 0;
    struct cfl_list *head;
    struct cfl_list *head_scope_span;
    struct cfl_list *tmp;
    struct cfl_list *tmp_scope_span;
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span *scope_span;

    cfl_list_foreach_safe(head, tmp, &ctr->resource_spans) {
        resource_span = cfl_list_entry(head, struct ctrace_resource_span, _head);

        /* iterate scope spans */
        cfl_list_foreach_safe(head_scope_span, tmp_scope_span, &resource_span->scope_spans) {
            scope_span = cfl_list_entry(head_scope_span, struct ctrace_scope_span, _head);
            if (cfl_list_is_empty(&scope_span->spans)) {
                ctr_scope_span_destroy(scope_span);
            }
        }

        /* check if resource span is now empty */
        if (cfl_list_is_empty(&resource_span->scope_spans)) {
            cfl_list_del(&resource_span->_head);
            ctr_resource_span_destroy(resource_span);
            count++;
        }
    }

    return count;
}

static void debug_trace(struct sampling *ctx, struct ctrace *ctr, int is_before)
{
    char tmp[128];
    struct sampling_span_registry *reg = NULL;

    reg = sampling_span_registry_create(UINT64_MAX);
    if (!reg) {
        return;
    }

    sampling_span_registry_add_trace(ctx, reg, ctr);
    if (is_before) {
        snprintf(tmp, sizeof(tmp) - 1, "Debug sampling '%s' (%p): before", ctx->type_str, ctr);
        sampling_span_registry_print(ctx, reg, tmp);
    }
    else {
        snprintf(tmp, sizeof(tmp) - 1, "Debug sampling '%s' (%p): after", ctx->type_str, ctr);
        sampling_span_registry_print(ctx, reg, tmp);
    }

    sampling_span_registry_remove_trace(ctx, reg, ctr);
    sampling_span_registry_destroy(reg);
}

static int cb_process_traces(struct flb_processor_instance *ins,
                             struct ctrace *in_ctr,
                             struct ctrace **out_ctr,
                             const char *tag,
                             int tag_len)
{
    int ret;
    int count;
    struct sampling *ctx = ins->context;

    /* just a quick check for developers */
    if (!ctx->plugin->cb_do_sampling) {
        flb_plg_error(ins, "unimplemented sampling callback for type '%s'", ctx->type_str);
        return -1;
    }

    if (ctx->debug_mode) {
        debug_trace(ctx, in_ctr, FLB_TRUE);
    }

    *out_ctr = in_ctr;

    /* do sampling: the callback will modify the ctrace context */
    ret = ctx->plugin->cb_do_sampling(ctx, ctx->plugin_context, in_ctr, out_ctr);

    if (ret != FLB_PROCESSOR_SUCCESS) {
        return ret;
    }

    if (ctx->debug_mode && *out_ctr) {
        debug_trace(ctx, *out_ctr, FLB_FALSE);
    }

    /* check if the ctrace context has empty resource spans */
    if (*out_ctr) {
        count = clean_empty_resource_spans(*out_ctr);
        flb_plg_trace(ins, "cleaned %i empty resource spans", count);
    }

    return ret;
}

static int cb_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    int ret;
    struct sampling *ctx;
    struct flb_processor *processor;

    processor = processor_instance->pu->parent;

    /* create main plugin context */
    ctx = sampling_config_create(processor_instance, config);
    if (!ctx) {
        return FLB_PROCESSOR_FAILURE;
    }
    if (ctx->type == SAMPLING_TYPE_TAIL &&
        (processor_instance->event_type != FLB_PROCESSOR_TRACES ||
         processor->source_plugin_type != FLB_PLUGIN_INPUT)) {
        flb_plg_error(processor_instance, "tail sampling requires an input traces pipeline");
        sampling_config_destroy(config, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ret = sampling_config_process_rules(config, ctx);
    if (ret == -1) {
        flb_plg_error(processor_instance, "failed to parse sampling rules");
        sampling_config_destroy(config, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ret = ctx->plugin->cb_init(config, ctx);
    if (ret != 0) {
        sampling_config_destroy(config, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    processor_instance->context = ctx;
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *processor_instance, void *data)
{
    if (processor_instance != NULL && data != NULL) {
        sampling_config_destroy(processor_instance->config, data);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "type", NULL,
        0, FLB_TRUE, offsetof(struct sampling, type_str),
        "Type of the sampling processor"
    },
    {
        FLB_CONFIG_MAP_BOOL, "debug", "false",
        0, FLB_TRUE, offsetof(struct sampling, debug_mode),
        "Enable debug mode where it prints the trace and it spans"
    },
    {
        FLB_CONFIG_MAP_VARIANT, "sampling_settings", NULL,
        0, FLB_TRUE, offsetof(struct sampling, sampling_settings),
        "Sampling rules, these are defined by the sampling processor/type"
    },
    {
        FLB_CONFIG_MAP_VARIANT, "conditions", NULL,
        0, FLB_TRUE, offsetof(struct sampling, conditions),
        "Sampling conditions"
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_sampling_plugin = {
    .name               = "sampling",
    .description        = "Sampling",
    .cb_init            = cb_init,
    .cb_process_logs    = sampling_probabilistic_logs,
    .cb_process_metrics = sampling_probabilistic_metrics,
    .cb_process_traces  = cb_process_traces,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
