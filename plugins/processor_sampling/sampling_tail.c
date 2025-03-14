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

#include "sampling.h"
#include "sampling_span_registry.h"

struct sampling_rule {
    int decision_wait;

    /* internal */
    void *parent;                   /* struct sampling *ctx */
    uint64_t decision_wait_ms;
    struct sampling_span_registry *span_reg;
};

/* we don't have any options (yet) */
static struct flb_config_map rules_config_map[] = {
    {
        FLB_CONFIG_MAP_TIME, "decision_wait", "30s",
        0, FLB_TRUE, offsetof(struct sampling_rule, decision_wait),
    },

    /* EOF */
    {0}
};

static void cb_timer_flush(struct flb_config *config, void *data)
{
    int ret;
    struct flb_input_instance *ins;
    struct cfl_list *head;
    struct sampling_rule *rule;
    struct trace_entry *entry;
    struct sampling *ctx;

    rule = (struct sampling_rule *) data;
    ctx = rule->parent;

    printf("timer flush: rule ptr=%p\n", rule);
    sampling_span_registry_print(ctx, rule->span_reg, "tail");
    // ctx = (struct buffered_trace *) data;
    // flb_plg_info(ctx->ins, "flush callback");

    // int i = 0;

    // ins = flb_processor_get_input_instance(ctx->ins->pu);

    // cfl_list_foreach(head, &ctx->list) {
    //     entry = cfl_list_entry(head, struct trace_entry, _head);
    //     printf("[%i] entry ctr: %p\n", i, entry->ctr);

    //     ret = flb_input_trace_append_skip_processor_stages(ins,
    //                                                        ctx->ins->pu->stage + 1,
    //                                                        entry->tag, cfl_sds_len(entry->tag),
    //                                                        entry->ctr);
    // }
}

static int cb_init(struct flb_config *config, struct sampling *ctx)
{
    int ret;
    struct sampling_rule *rule;
    struct flb_sched *sched;

    flb_plg_info(ctx->ins, "initializing 'tail' sampling processor");

    rule = flb_calloc(1, sizeof(struct sampling_rule));
    if (!rule) {
        flb_errno();
        return -1;
    }
    rule->parent = ctx;

    /* get the scheduler context */
    sched = flb_sched_ctx_get();
    if (!sched) {
        flb_plg_error(ctx->ins, "could not get scheduler context");
        return -1;
    }

    ret = flb_config_map_set(&ctx->plugin_rules_properties, ctx->plugin_config_map, (void *) rule);
    if (ret == -1) {
        flb_free(rule);
        return -1;
    }

    /* convert decision wait to milliseconds*/
    rule->decision_wait_ms = rule->decision_wait * 1000;

        /* set a timer callback */
    ret = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_PERM,
                                    rule->decision_wait_ms, cb_timer_flush,
                                    rule, NULL);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not create timer");
        flb_free(rule);
        return -1;
    }

    rule->span_reg = sampling_span_registry_create();
    if (!rule->span_reg) {
        flb_plg_error(ctx->ins, "could not span registry");
        flb_free(rule);
        return -1;
    }

    printf("init rule ptr=%p\n", rule);
    sampling_set_context(ctx, rule);
    return 0;
}

static int cb_do_sampling(struct sampling *ctx, void *plugin_context,
                          struct ctrace *in_ctr, struct ctrace **out_ctr)
{
    int ret;
    struct sampling_rule *rule = plugin_context;

    ret = sampling_span_registry_add_trace(ctx, rule->span_reg, in_ctr);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to add trace to span registry");
        return -1;
    }

    *out_ctr = NULL;

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_config *config, void *data)
{
     struct sampling_rule *rule = data;

     if (rule) {
         flb_free(rule);
     }
     return 0;
}

struct sampling_plugin sampling_tail_plugin = {
    .type           = SAMPLING_TYPE_TAIL,
    .name           = "tail",
    .config_map     = rules_config_map,
    .cb_init        = cb_init,
    .cb_do_sampling = cb_do_sampling,
    .cb_exit        = cb_exit,
};
