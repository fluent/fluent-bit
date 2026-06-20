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

#include "sampling.h"
#include "sampling_span_registry.h"

/*
 * You can use this plugin as a base for the next sampling processor...
 */

struct sampling_rule {
    int empty;
};

/* we don't have any options (yet) */
static struct flb_config_map rules_config_map[] = {
    /* EOF */
    {0}
};

static int cb_init(struct flb_config *config, struct sampling *ctx)
{
    return 0;
}

static int cb_do_sampling(struct sampling *ctx, void *plugin_context,
                          struct ctrace *in_ctr, struct ctrace **out_ctr)
{
    int ret;
    struct sampling_span_registry *span_reg;

    span_reg = sampling_span_registry_create();
    if (!span_reg) {
        return -1;
    }

    ret = sampling_span_registry_add_trace(ctx, span_reg, in_ctr);
    if (ret == -1) {
        sampling_span_registry_destroy(span_reg);
        flb_plg_error(ctx->ins, "failed to add trace to span registry");
        return -1;
    }

    sampling_span_registry_print(ctx, span_reg, "test");
    sampling_span_registry_destroy(span_reg);

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

struct sampling_plugin sampling_test_plugin = {
    .type           = SAMPLING_TYPE_TEST,
    .name           = "test",
    .config_map     = rules_config_map,
    .cb_init        = cb_init,
    .cb_do_sampling = cb_do_sampling,
    .cb_exit        = cb_exit,
};
