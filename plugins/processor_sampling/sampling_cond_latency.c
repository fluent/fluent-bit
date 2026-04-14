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

struct cond_latency {
    uint64_t threshold_ms_low;
    uint64_t threshold_ms_high;
};

int cond_latency_check(struct sampling_condition *sampling_condition, struct ctrace_span *span)
{
    uint64_t latency;
    struct cond_latency *ctx = sampling_condition->type_context;


    if (span->start_time_unix_nano > span->end_time_unix_nano) {
        return FLB_FALSE;
    }

    /* get the latency in milliseconds */
    latency = (span->end_time_unix_nano - span->start_time_unix_nano) / 1000000;

    /* check if the latency is within either of the thresholds */
    if ((ctx->threshold_ms_low != 0 && latency <= ctx->threshold_ms_low) ||
        (ctx->threshold_ms_high != 0 && latency >= ctx->threshold_ms_high)) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

struct sampling_condition *cond_latency_create(struct sampling *ctx,
                                               struct sampling_conditions *sampling_conditions,
                                               struct cfl_variant *settings)
{
    struct cond_latency *cond;
    struct cfl_variant *var;
    struct sampling_condition *sampling_condition;

    cond = flb_calloc(1, sizeof(struct cond_latency));
    if (!cond) {
        flb_errno();
        return NULL;
    }
    cond->threshold_ms_low = 0;
    cond->threshold_ms_high = 0;

    /* threshold_ms_low */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "threshold_ms_low");
    if (var) {
        if (var->type != CFL_VARIANT_UINT) {
            flb_plg_error(ctx->ins, "threshold_ms_low must be an unsigned integer");
            flb_free(cond);
            return NULL;
        }

        cond->threshold_ms_low = var->data.as_uint64;
    }

    /* threshold_ms_high */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "threshold_ms_high");
    if (var) {
        if (var->type != CFL_VARIANT_UINT) {
            flb_plg_error(ctx->ins, "threshold_ms_high must be an unsigned integer");
            flb_free(cond);
            return NULL;
        }
        cond->threshold_ms_high = var->data.as_uint64;
    }

    if (cond->threshold_ms_low == 0 && cond->threshold_ms_high == 0) {
        flb_plg_error(ctx->ins, "either threshold_ms_low or threshold_ms_high must be set");
        flb_free(cond);
        return NULL;
    }

    sampling_condition = flb_calloc(1, sizeof(struct sampling_condition));
    if (!sampling_condition) {
        flb_errno();
        flb_free(cond);
        return NULL;
    }
    sampling_condition->type = SAMPLING_COND_LATENCY;
    sampling_condition->type_context = cond;
    cfl_list_add(&sampling_condition->_head, &sampling_conditions->list);

    return sampling_condition;

}

void cond_latency_destroy(struct sampling_condition *sampling_condition)
{
    struct cond_latency *cond = sampling_condition->type_context;
    flb_free(cond);
}
