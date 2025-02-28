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
#include "sampling.h"

#ifndef htonll
static inline uint64_t htonll(uint64_t value) {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        return ((uint64_t) htonl (value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
    #else
        /* this is already big-endian, there is no need to swap */
        return value;
    #endif
}
#endif

struct sampling_rule {
    int sampling_percentage;
};

static struct flb_config_map rules_config_map[] = {
    {
        FLB_CONFIG_MAP_INT, "sampling_percentage", "10",
        0, FLB_TRUE, offsetof(struct sampling_rule, sampling_percentage),
    },

    /* EOF */
    {0}
};

static int cb_init(struct flb_config *config, struct sampling *ctx)
{
    int ret;
    struct sampling_rule *rule;

    flb_plg_info(ctx->ins, "initializing probabilistic sampling processor");

    rule = flb_calloc(1, sizeof(struct sampling_rule));
    if (!rule) {
        flb_errno();
        return -1;
    }

    ret = flb_config_map_set(&ctx->plugin_rules_properties, ctx->plugin_config_map, (void *) rule);
    if (ret == -1) {
        flb_free(rule);
        return -1;
    }

    sampling_set_context(ctx, rule);

    return 0;
}

/* Extract the first 8 bytes of trace_id */
static uint64_t extract_trace_id(cfl_sds_t trace_id) {
    uint64_t trace_number = 0;

    if (cfl_sds_len(trace_id) < 16) {
        /* invalid trace_id */
        return 0;
    }

    memcpy(&trace_number, trace_id, 8);

    /* convert to big-endian (if needed) */
    trace_number = htonll(trace_number);
    return trace_number;
}

static int check_sampling(cfl_sds_t trace_id, double sampling_percentage)
{
    uint64_t trace_number;
    double hash_value;

    trace_number = extract_trace_id(trace_id);

    /* normalize hash value */
    hash_value = (trace_number % 1000000) / 10000.0;

    /* compare with the sampling percentage */
    return hash_value < sampling_percentage;
}

static int cb_do_sampling(struct sampling *ctx, void *plugin_context, struct ctrace *ctr)
{
    int ret;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct ctrace_span *span;
    struct sampling_rule *rule = (struct sampling_rule *) plugin_context;

    cfl_list_foreach_safe(head, tmp, &ctr->span_list) {
        span = cfl_list_entry(head, struct ctrace_span, _head_global);
        ret = check_sampling(span->trace_id->buf, rule->sampling_percentage);
        if (ret == 1) {
            /* we keep the span, all good */
        }
        else {
            /* remove the span */
            ctr_span_destroy(span);
        }
    }

    return 0;
}

static int cb_exit(struct flb_config *config, void *data)
{
    struct sampling_rule *rule = data;

    if (rule) {
        flb_free(rule);
    }

    return 0;
}

struct sampling_plugin sampling_probabilistic_plugin = {
    .type           = SAMPLING_TYPE_PROBABILISTIC,
    .name           = "probabilistic",
    .config_map     = rules_config_map,
    .cb_init        = cb_init,
    .cb_do_sampling = cb_do_sampling,
    .cb_exit        = cb_exit,
};
